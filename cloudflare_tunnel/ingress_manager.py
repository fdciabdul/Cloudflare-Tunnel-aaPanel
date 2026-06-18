#!/usr/bin/python
# coding: utf-8
# Manages the ingress section of /etc/cloudflared/config.yml and (optionally)
# the public CNAME on Cloudflare for each hostname.

import json
import os
import re
import subprocess

import public

from tunnel_manager import CERT_PATH, CLOUDFLARED_BIN, CLOUDFLARED_HOME, CONFIG_PATH, SERVICE_NAME


def _yaml_escape(s):
    # We only emit simple scalars (hostnames, http://host:port, http_status:404).
    # Wrap in double quotes if the value contains anything that could be tricky.
    if re.match(r"^[A-Za-z0-9_./:\-]+$", s):
        return s
    return '"{}"'.format(s.replace('"', '\\"'))


class IngressManager:
    def __init__(self):
        self.plugin_dir = os.path.dirname(os.path.abspath(__file__))
        self.data_dir = os.path.join(self.plugin_dir, "data")
        if not os.path.exists(self.data_dir):
            os.makedirs(self.data_dir)
        self.ingress_file = os.path.join(self.data_dir, "ingress.json")
        self.state_file = os.path.join(self.data_dir, "state.json")

    # ---------- persistence ----------
    def _read_ingress(self):
        if not os.path.exists(self.ingress_file):
            return []
        try:
            return json.loads(public.readFile(self.ingress_file) or "[]")
        except Exception:
            return []

    def _write_ingress(self, items):
        public.writeFile(self.ingress_file, json.dumps(items, indent=2))

    def _read_state(self):
        if not os.path.exists(self.state_file):
            return {}
        try:
            return json.loads(public.readFile(self.state_file) or "{}")
        except Exception:
            return {}

    # ---------- list ----------
    def get_ingress(self, get):
        return {"status": True, "msg": "ok", "data": self._read_ingress()}

    # ---------- add ----------
    def add_ingress(self, get):
        hostname = (get.hostname or "").strip().lower() if hasattr(get, "hostname") else ""
        service = (get.service or "").strip() if hasattr(get, "service") else ""
        proxied = True
        if hasattr(get, "proxied"):
            proxied = str(get.proxied).lower() not in ("0", "false", "no")
        auto_dns = True
        if hasattr(get, "auto_dns"):
            auto_dns = str(get.auto_dns).lower() not in ("0", "false", "no")
        zone_id = (get.zone_id or "").strip() if hasattr(get, "zone_id") else ""

        if not re.match(r"^[a-z0-9.\-*]+\.[a-z]{2,}$", hostname):
            return public.returnMsg(False, "Invalid hostname")
        if not re.match(r"^(https?://[^\s]+|tcp://[^\s]+|ssh://[^\s]+|unix:/[^\s]+|http_status:\d+|hello_world)$", service):
            return public.returnMsg(False, "Service must look like http://127.0.0.1:8080 or http_status:404")

        state = self._read_state()
        tunnel_id = state.get("active_tunnel_id", "")
        if not tunnel_id:
            return public.returnMsg(False, "Select an active tunnel first")

        # When DNS automation is on, validate creds BEFORE we mutate ingress.json — that
        # way a missing token doesn't leave a half-saved rule the user has to clean up.
        if auto_dns:
            from dns_manager import DnsManager
            dns = DnsManager()
            auth, source = dns._load_credentials()
            if not auth:
                return public.returnMsg(False, "Auto-CNAME is on but no Cloudflare credentials found. Set a token in Auth tab or configure cloudflare_manage, or uncheck Auto-create CNAME.")

        prev_items = self._read_ingress()
        items = [i for i in prev_items if i.get("hostname") != hostname]
        items.append({"hostname": hostname, "service": service, "proxied": proxied, "zone_id": zone_id})
        self._write_ingress(items)

        dns_msg = "DNS not touched"
        if auto_dns:
            target = "{}.cfargotunnel.com".format(tunnel_id)
            ok, dns_msg = dns.upsert_cname(hostname, target, zone_id=zone_id, proxied=proxied)
            if not ok:
                # Roll back — user asked for an atomic add.
                self._write_ingress(prev_items)
                return public.returnMsg(False, "DNS failed, rule NOT saved: " + dns_msg)

        applied = self.apply_config(get)
        if not applied.get("status"):
            self._write_ingress(prev_items)
            return public.returnMsg(False, "Apply failed, rule NOT saved: " + applied.get("msg", ""))
        return public.returnMsg(True, "Hostname added. " + dns_msg)

    # ---------- remove ----------
    def remove_ingress(self, get):
        hostname = (get.hostname or "").strip().lower() if hasattr(get, "hostname") else ""
        if not hostname:
            return public.returnMsg(False, "Missing hostname")
        delete_dns = True
        if hasattr(get, "delete_dns"):
            delete_dns = str(get.delete_dns).lower() not in ("0", "false", "no")

        items = self._read_ingress()
        target = next((i for i in items if i.get("hostname") == hostname), None)
        if not target:
            return public.returnMsg(False, "Hostname not in ingress list")
        items = [i for i in items if i.get("hostname") != hostname]
        self._write_ingress(items)

        dns_msg = "DNS not touched"
        if delete_dns:
            from dns_manager import DnsManager
            ok, msg = DnsManager().delete_cname(hostname, zone_id=target.get("zone_id", ""))
            dns_msg = msg
            # Don't fail the whole remove if DNS cleanup fails.

        applied = self.apply_config(get)
        if not applied.get("status"):
            return public.returnMsg(False, "Rule removed, DNS: {}; apply failed: {}".format(dns_msg, applied.get("msg")))
        return public.returnMsg(True, "Hostname removed. " + dns_msg)

    # ---------- write config.yml + restart service ----------
    def _tunnel_creds(self, tunnel_id):
        """Return (path, "") to a credentials-file for this tunnel, materializing one from
        `cloudflared tunnel token --cred-file` if no .json exists on disk. We always emit a
        credentials-file because `cloudflared service install` rejects token-only configs."""
        cred_path = os.path.join(CLOUDFLARED_HOME, "{}.json".format(tunnel_id))
        if os.path.exists(cred_path):
            return cred_path, ""
        legacy = os.path.expanduser("~/.cloudflared/{}.json".format(tunnel_id))
        if os.path.exists(legacy):
            try:
                os.rename(legacy, cred_path)
                return cred_path, ""
            except Exception:
                return legacy, ""
        if not os.path.exists(CLOUDFLARED_BIN) or not os.path.exists(CERT_PATH):
            return None, "no credentials file, and cloudflared/cert.pem unavailable"
        env = os.environ.copy()
        env["TUNNEL_ORIGIN_CERT"] = CERT_PATH
        try:
            r = subprocess.run(
                [CLOUDFLARED_BIN, "tunnel", "token", "--cred-file", cred_path, tunnel_id],
                capture_output=True, text=True, timeout=20, env=env,
            )
            if r.returncode != 0 or not os.path.exists(cred_path):
                return None, "token-to-credfile failed: " + (r.stderr or r.stdout or "unknown")
            os.chmod(cred_path, 0o600)
            return cred_path, ""
        except Exception as e:
            return None, "credfile materialize error: {}".format(e)

    def apply_config(self, get):
        state = self._read_state()
        tunnel_id = state.get("active_tunnel_id", "")
        if not tunnel_id:
            return public.returnMsg(False, "No active tunnel selected")

        cred_path, err = self._tunnel_creds(tunnel_id)
        if not cred_path:
            return public.returnMsg(False, err)

        items = self._read_ingress()
        lines = [
            "# Managed by AAPanel Cloudflare Tunnel plugin. Edits will be overwritten.",
            "tunnel: {}".format(tunnel_id),
            "credentials-file: {}".format(cred_path),
            "ingress:",
        ]
        for it in items:
            lines.append("  - hostname: {}".format(_yaml_escape(it["hostname"])))
            lines.append("    service: {}".format(_yaml_escape(it["service"])))
        # Catch-all is required by cloudflared.
        lines.append("  - service: http_status:404")
        public.writeFile(CONFIG_PATH, "\n".join(lines) + "\n")
        os.chmod(CONFIG_PATH, 0o600)

        # If the systemd service exists, restart it; otherwise leave it to the user.
        if os.system("systemctl list-unit-files | grep -q '^{}'".format(SERVICE_NAME)) == 0:
            os.system("systemctl restart {} 2>/dev/null".format(SERVICE_NAME))
        return public.returnMsg(True, "Config written to " + CONFIG_PATH)
