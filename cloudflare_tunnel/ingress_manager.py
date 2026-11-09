#!/usr/bin/python
# coding: utf-8
# Manages the ingress section of /etc/cloudflared/config.yml and (optionally)
# the public CNAME on Cloudflare for each hostname.

import json
import os
import re
import subprocess
import tempfile
from urllib.parse import urljoin, urlsplit

import requests
from .storage import read_json, write_json, atomic_write, serialized, tunnel_uuid

import public

from .tunnel_manager import CERT_PATH, CLOUDFLARED_BIN, CLOUDFLARED_HOME, CONFIG_PATH, SERVICE_NAME
# CERT_PATH is legacy shared cert.pem — v1.3.0 falls back to per-profile certs first,
# only touching CERT_PATH when the migration hasn't run yet.


# Allowlist for originRequest keys so typos don't silently reach config.yml. Each entry
# is (key, type). Types map to how we coerce/emit the value:
#   bool     → true|false
#   duration → passthrough string, must match ^(?:\d+(?:ns|us|ms|s|m|h))+$
#   int      → integer
#   string   → YAML-escaped scalar
ORIGIN_REQUEST_FIELDS = {
    "connectTimeout":         "duration",
    "tlsTimeout":             "duration",
    "tcpKeepAlive":           "duration",
    "keepAliveTimeout":       "duration",
    "keepAliveConnections":   "int",
    "noHappyEyeballs":        "bool",
    "noTLSVerify":            "bool",
    "disableChunkedEncoding": "bool",
    "http2Origin":            "bool",
    "httpHostHeader":         "string",
    "originServerName":       "string",
    "caPool":                 "string",
    "proxyAddress":           "string",
    "proxyPort":              "int",
    "proxyType":              "string",
}


def _yaml_escape(s):
    return json.dumps(str(s), ensure_ascii=True)

def _coerce_origin_request(raw):
    """Sanitize a dict of user-supplied originRequest values. Unknown keys and blanks
    are dropped; type mismatches raise ValueError so the API returns a clean message."""
    if not raw:
        return {}
    if not isinstance(raw, dict):
        raise ValueError("origin_request must be an object")
    out = {}
    for k, v in raw.items():
        if k not in ORIGIN_REQUEST_FIELDS:
            continue
        if v in ("", None):
            continue
        kind = ORIGIN_REQUEST_FIELDS[k]
        if kind == "bool":
            if isinstance(v, bool):
                out[k] = v
            elif isinstance(v, str):
                out[k] = v.lower() in ("1", "true", "yes", "on")
            else:
                raise ValueError("{}: expected boolean".format(k))
        elif kind == "int":
            try:
                out[k] = int(v)
            except Exception:
                raise ValueError("{}: expected integer".format(k))
        elif kind == "duration":
            s = str(v).strip()
            if not re.match(r"^(?:\d+(?:ns|us|ms|s|m|h))+$", s):
                raise ValueError("{}: expected duration like '30s' or '1m30s'".format(k))
            out[k] = s
        else:
            out[k] = str(v).strip()
    return out


def _emit_yaml_value(v):
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, int):
        return str(v)
    return _yaml_escape(str(v))


def _origin_options(item):
    options = dict(item.get("origin_request") or {})
    hostname = item.get("hostname", "")
    # aaPanel selects a virtual host by domain, not by the loopback address.
    # Wildcard routes must retain the actual incoming Host instead of sending '*.'.
    if item.get("service", "").startswith(("http://", "https://")) and hostname and not hostname.startswith("*."):
        options.setdefault("httpHostHeader", hostname)
    return options


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
        return read_json(self.ingress_file, [])

    def _write_ingress(self, items):
        write_json(self.ingress_file, items)

    def _read_state(self):
        return read_json(self.state_file, {})

    def _apply_items(self, items, get):
        previous = self._read_ingress()
        try:
            self._write_ingress(items)
            result = self.apply_config(get)
            if not result.get("status"):
                self._write_ingress(previous)
            return result
        except Exception as exc:
            self._write_ingress(previous)
            return public.returnMsg(False, str(exc))

    # ---------- list ----------
    def get_ingress(self, get):
        return {"status": True, "msg": "ok", "data": self._read_ingress()}

    def check_origin(self, get):
        hostname = getattr(get, "hostname", "").strip().lower()
        item = next((row for row in self._read_ingress() if row.get("hostname") == hostname), None)
        if not item:
            return public.returnMsg(False, "Save the hostname before checking its origin")
        service = item.get("service", "")
        if not service.startswith("http://"):
            return public.returnMsg(False, "This check is for local HTTP services")
        if hostname.startswith("*."):
            return public.returnMsg(False, "Check a concrete hostname instead of a wildcard")
        host = _origin_options(item).get("httpHostHeader", hostname)
        try:
            # Match a public HTTPS request's forwarded scheme. Never follow a
            # redirect back through Cloudflare or read an unbounded response body.
            with requests.Session() as session:
                session.trust_env = False
                with session.get(service, headers={"Host": host, "X-Forwarded-Proto": "https"},
                                 timeout=(3, 5), allow_redirects=False, stream=True) as response:
                    code = response.status_code
                    location = response.headers.get("Location", "")
            detail = "Local origin returned HTTP {} for Host {}. ".format(code, host)
            if code == 404:
                return public.returnMsg(False, detail + "Check the aaPanel site's domain binding, document root/index and error log, including PHP open_basedir restrictions. This 404 came from the local website, before Cloudflare.")
            if 300 <= code < 400 and location and urlsplit(urljoin(service, location)).scheme == "https":
                return public.returnMsg(False, detail + "The origin redirects to HTTPS. To keep local HTTP, turn off Force HTTPS for this aaPanel site or adjust the application's redirect. Cloudflare can provide visitor HTTPS without a local certificate.")
            return public.returnMsg(200 <= code < 400, detail + ("The local HTTP service responds. If the public URL still fails, check the exact tunnel hostname and CNAME." if code < 400 else "Check the site's application and web server logs."))
        except requests.RequestException as exc:
            return public.returnMsg(False, "Could not reach local HTTP service {}. Check that the website is running and listening on this port. {}".format(service, exc))

    # ---------- add ----------
    @serialized
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

        try:
            hostname = hostname.rstrip(".").encode("idna").decode("ascii")
        except UnicodeError:
            return public.returnMsg(False, "Invalid hostname")
        # Optional originRequest config; UI sends a JSON blob to keep the wire format small.
        origin_request = {}
        if hasattr(get, "origin_request_json") and get.origin_request_json:
            try:
                raw = json.loads(get.origin_request_json)
                origin_request = _coerce_origin_request(raw)
            except ValueError as e:
                return public.returnMsg(False, "Invalid origin request: " + str(e))
            except Exception:
                return public.returnMsg(False, "origin_request_json must be valid JSON")

        host_labels = hostname[2:] if hostname.startswith("*.") else hostname
        if len(hostname) > 253 or "." not in host_labels or any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in host_labels.split(".")):
            return public.returnMsg(False, "Invalid hostname")
        if not re.match(r"^(https?://[^\s]+|tcp://[^\s]+|ssh://[^\s]+|unix:/[^\s]+|http_status:\d+|hello_world)$", service):
            return public.returnMsg(False, "Service must look like http://127.0.0.1:80 or http_status:404")

        state = self._read_state()
        tunnel_id = state.get("active_tunnel_id", "")
        if not tunnel_id:
            return public.returnMsg(False, "Select an active tunnel first")

        try:
            tunnel_id = tunnel_uuid(tunnel_id)
        except ValueError as exc:
            return public.returnMsg(False, str(exc))
        from .dns_manager import DnsManager
        dns = DnsManager()
        tunnel_profile = dns.find_profile(state.get("active_profile_id", "")) or {}
        change = None
        target = "{}.cfargotunnel.com".format(tunnel_id)
        if auto_dns:
            try:
                change = dns.prepare_cname(hostname, target, zone_id, proxied, profile_id=getattr(get, "dns_profile_id", ""), account_id=tunnel_profile.get("account_id", ""))
            except ValueError as exc:
                return public.returnMsg(False, "DNS not changed; rule not saved: " + str(exc))

        prev_items = self._read_ingress()
        # Preserve any previously-configured origin_request if the caller didn't send one
        # explicitly — matches expected behaviour when the form omits the Advanced block.
        prior = next((i for i in prev_items if i.get("hostname") == hostname), None)
        if prior and not origin_request and not (hasattr(get, "origin_request_json") and get.origin_request_json):
            origin_request = prior.get("origin_request") or {}
        items = [i for i in prev_items if i.get("hostname") != hostname]
        row = dict(prior or {}, hostname=hostname, service=service, proxied=proxied, zone_id=zone_id, auto_dns=auto_dns)
        if origin_request:
            row["origin_request"] = origin_request
        items.append(row)
        dns_msg = "Manual DNS required: create a CNAME named {} with target {}, TTL Auto, proxy {}.".format(hostname, target, "Proxied (orange cloud)" if proxied else "DNS only (gray cloud). Public HTTP/HTTPS Tunnel applications normally require Proxied")
        if change:
            try:
                dns_msg = dns.commit_cname(change)
            except ValueError as exc:
                return public.returnMsg(False, "DNS failed; rule not saved: " + str(exc))
            row.update(zone_id=change["zone_id"], dns_profile_id=change["profile_id"], dns_record_id=change["record_id"], dns_target=target)
        applied = self._apply_items(items, get)
        if not applied.get("status"):
            rollback = ""
            if change:
                try:
                    dns.rollback_cname(change)
                    rollback = " DNS restored."
                except Exception as exc:
                    rollback = " DNS rollback failed; manual repair required: " + str(exc)
            return public.returnMsg(False, "Apply failed; rule not saved: " + applied.get("msg", "") + rollback)
        return {"status": True, "msg": "Hostname added. " + dns_msg,
                "data": {"manual_dns": None if auto_dns else {"type": "CNAME", "name": hostname, "content": target, "proxied": proxied, "ttl": "Auto"}}}

    # ---------- edit options (no DNS side-effects) ----------
    @serialized
    def set_ingress_options(self, get):
        hostname = (get.hostname or "").strip().lower() if hasattr(get, "hostname") else ""
        if not hostname:
            return public.returnMsg(False, "Missing hostname")
        items = self._read_ingress()
        target = next((i for i in items if i.get("hostname") == hostname), None)
        if not target:
            return public.returnMsg(False, "Hostname not in ingress list — add it first")

        if hasattr(get, "service") and get.service:
            service = get.service.strip()
            if not re.match(r"^(https?://[^\s]+|tcp://[^\s]+|ssh://[^\s]+|unix:/[^\s]+|http_status:\d+|hello_world)$", service):
                return public.returnMsg(False, "Service must look like http://127.0.0.1:80 or http_status:404")
            target["service"] = service

        if hasattr(get, "origin_request_json"):
            raw_json = (get.origin_request_json or "").strip()
            if raw_json in ("", "{}", "null"):
                target.pop("origin_request", None)
            else:
                try:
                    raw = json.loads(raw_json)
                    target["origin_request"] = _coerce_origin_request(raw)
                except ValueError as e:
                    return public.returnMsg(False, "Invalid origin request: " + str(e))
                except Exception:
                    return public.returnMsg(False, "origin_request_json must be valid JSON")

        applied = self._apply_items(items, get)
        if not applied.get("status"):
            return public.returnMsg(False, "Options not saved; apply failed: " + applied.get("msg", ""))
        return public.returnMsg(True, "Options updated")

    # ---------- remove ----------
    @serialized
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
        previous = items
        items = [i for i in items if i.get("hostname") != hostname]
        applied = self._apply_items(items, get)
        if not applied.get("status"):
            return public.returnMsg(False, "Rule kept; apply failed: " + applied.get("msg", ""))
        dns_msg = "DNS kept; remove its CNAME manually if no longer needed"
        if delete_dns and target.get("dns_record_id"):
            from .dns_manager import DnsManager
            ok, dns_msg = DnsManager().delete_cname(hostname, zone_id=target.get("zone_id", ""), target=target.get("dns_target", ""), profile_id=target.get("dns_profile_id", ""), record_id=target.get("dns_record_id", ""))
            if not ok:
                restored = self._apply_items(previous, get)
                return public.returnMsg(False, "DNS cleanup failed: {}. {} Check DNS before retrying.".format(dns_msg, "Rule restored." if restored.get("status") else "Rule restoration failed: " + restored.get("msg", "")))
        return public.returnMsg(True, "Hostname removed. " + dns_msg)

    # ---------- write config.yml + restart service ----------
    def _cert_for_active_tunnel(self):
        """Return the cert.pem path that owns the currently-active tunnel. Prefer the
        active profile stored in state.json (v1.3.0), fall back to any logged-in profile,
        and lastly the legacy shared cert.pem (pre-1.3.0 installs)."""
        state = self._read_state()
        pid = state.get("active_profile_id", "")
        if pid:
            from .dns_manager import DnsManager
            p = DnsManager().find_profile(pid)
            if p and p.get("cert_path") and os.path.exists(p["cert_path"]):
                return p["cert_path"]
        # No stored profile — try any logged-in one (single-profile installs work fine).
        from .dns_manager import DnsManager
        for p in DnsManager()._all_profiles():
            if p.get("cert_path") and os.path.exists(p["cert_path"]):
                return p["cert_path"]
        if os.path.exists(CERT_PATH):
            return CERT_PATH
        return ""

    def _tunnel_creds(self, tunnel_id):
        """Return (path, "") to a credentials-file for this tunnel, materializing one from
        `cloudflared tunnel token --cred-file` if no .json exists on disk. We always emit a
        credentials-file because `cloudflared service install` rejects token-only configs."""
        try:
            tunnel_id = tunnel_uuid(tunnel_id)
        except ValueError as exc:
            return None, str(exc)
        cred_path = os.path.join(CLOUDFLARED_HOME, "{}.json".format(tunnel_id))
        if os.path.exists(cred_path):
            os.chmod(cred_path, 0o600)
            return cred_path, ""
        legacy = os.path.expanduser("~/.cloudflared/{}.json".format(tunnel_id))
        if os.path.exists(legacy):
            try:
                os.rename(legacy, cred_path)
                os.chmod(cred_path, 0o600)
                return cred_path, ""
            except OSError as exc:
                return None, "Could not relocate credentials: " + str(exc)
        # API-only profiles can recover credentials for existing local tunnels.
        from .dns_manager import DnsManager
        dns = DnsManager()
        profile = dns.find_profile(self._read_state().get("active_profile_id", ""))
        if profile and profile.get("token") and profile.get("account_id"):
            import base64
            result = dns._request("GET", "/accounts/{}/cfd_tunnel/{}/token".format(profile["account_id"], tunnel_id), dns._auth_for_profile(profile), profile["name"])
            if not result["status"]:
                return None, "Could not retrieve tunnel credentials: " + result["msg"]
            try:
                token = result["data"]
                payload = json.loads(base64.b64decode(token + "=" * (-len(token) % 4), validate=True))
                if payload["t"] != tunnel_id or payload["a"] != profile["account_id"] or not payload.get("s"):
                    raise ValueError("Tunnel token does not match selected account/tunnel")
                write_json(cred_path, {"AccountTag": payload["a"], "TunnelID": payload["t"], "TunnelSecret": payload["s"]})
                return cred_path, ""
            except (ValueError, TypeError, KeyError) as exc:
                return None, "Invalid tunnel credentials response: " + str(exc)
        # Materialize via `cloudflared tunnel token --cred-file <target> <tunnel-id>`
        # using the cert that owns this tunnel's account.
        cert = self._cert_for_active_tunnel()
        if not os.path.exists(CLOUDFLARED_BIN) or not cert:
            return None, "no credentials file, and no logged-in profile cert available to fetch a token"
        env = os.environ.copy()
        env["TUNNEL_ORIGIN_CERT"] = cert
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

    @serialized
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
            "tunnel: {}".format(_yaml_escape(tunnel_id)),
            "credentials-file: {}".format(_yaml_escape(cred_path)),
            "ingress:",
        ]
        for it in items:
            lines.append("  - hostname: {}".format(_yaml_escape(it["hostname"])))
            lines.append("    service: {}".format(_yaml_escape(it["service"])))
            origin = _origin_options(it)
            if origin:
                lines.append("    originRequest:")
                # Sort keys for deterministic output (nicer diffs on git-tracked config).
                for k in sorted(origin.keys()):
                    lines.append("      {}: {}".format(k, _emit_yaml_value(origin[k])))
        # Catch-all is required by cloudflared.
        lines.append("  - service: http_status:404")
        previous = public.readFile(CONFIG_PATH) if os.path.exists(CONFIG_PATH) else None
        fd, candidate = tempfile.mkstemp(prefix=".config-", suffix=".yml", dir=CLOUDFLARED_HOME)
        os.close(fd)
        existed = None
        was_active = False
        changed = False
        service_attempted = False
        try:
            atomic_write(candidate, "\n".join(lines) + "\n")
            checked = subprocess.run([CLOUDFLARED_BIN, "--config", candidate, "tunnel", "ingress", "validate"], capture_output=True, text=True, timeout=20)
            if checked.returncode:
                raise ValueError("Config validation failed: " + (checked.stderr or checked.stdout))
            loaded = subprocess.run(["systemctl", "show", SERVICE_NAME, "--property=LoadState", "--value"], capture_output=True, text=True, timeout=10)
            if loaded.returncode or not loaded.stdout.strip():
                raise ValueError("Could not query systemd: " + (loaded.stderr or loaded.stdout))
            existed = loaded.stdout.strip() != "not-found"
            if existed:
                was_active = subprocess.run(["systemctl", "is-active", "--quiet", SERVICE_NAME], capture_output=True, timeout=10).returncode == 0
            atomic_write(CONFIG_PATH, "\n".join(lines) + "\n")
            changed = True
            service_attempted = True
            if not existed:
                installed = subprocess.run([CLOUDFLARED_BIN, "--config", CONFIG_PATH, "service", "install"], capture_output=True, text=True, timeout=30)
                if installed.returncode:
                    raise ValueError("Service install failed: " + (installed.stderr or installed.stdout))
                enabled = subprocess.run(["systemctl", "enable", SERVICE_NAME], capture_output=True, text=True, timeout=30)
                if enabled.returncode:
                    raise ValueError("Service enable failed: " + (enabled.stderr or enabled.stdout))
            restarted = subprocess.run(["systemctl", "restart", SERVICE_NAME], capture_output=True, text=True, timeout=30)
            if restarted.returncode:
                raise ValueError("Service restart failed: " + (restarted.stderr or restarted.stdout))
            active = subprocess.run(["systemctl", "is-active", "--quiet", SERVICE_NAME], capture_output=True, timeout=10)
            if active.returncode:
                raise ValueError("Service did not remain active; inspect Advanced service log")
            return public.returnMsg(True, "Configuration applied; service active")
        except Exception as exc:
            repair = []
            if changed:
                try:
                    if previous is None:
                        os.unlink(CONFIG_PATH)
                    else:
                        atomic_write(CONFIG_PATH, previous)
                except OSError as restore_error:
                    repair.append("config restore failed: " + str(restore_error))
            if service_attempted:
                try:
                    if existed:
                        command = ["systemctl", "restart" if was_active else "stop", SERVICE_NAME]
                        restored = subprocess.run(command, capture_output=True, text=True, timeout=30)
                        if restored.returncode:
                            repair.append("service restore failed: " + (restored.stderr or restored.stdout))
                    else:
                        removed = subprocess.run([CLOUDFLARED_BIN, "service", "uninstall"], capture_output=True, text=True, timeout=30)
                        if removed.returncode:
                            repair.append("new service cleanup failed: " + (removed.stderr or removed.stdout))
                except Exception as restore_error:
                    repair.append("service restore failed: " + str(restore_error))
            return public.returnMsg(False, str(exc) + (". Manual repair required: " + "; ".join(repair) if repair else ". Previous config/service state restored."))
        finally:
            if os.path.exists(candidate):
                os.unlink(candidate)
