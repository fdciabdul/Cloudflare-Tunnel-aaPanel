#!/usr/bin/python
# coding: utf-8
# Manages the cloudflared binary, per-profile browser login, tunnel CRUD, and the
# systemd service. Every profile carries its own cert.pem so tunnel CRUD works across
# multiple Cloudflare accounts (v1.3.0).

import json
import os
import re
import subprocess
import time

import public

CLOUDFLARED_BIN = "/usr/local/bin/cloudflared"
CLOUDFLARED_HOME = "/etc/cloudflared"
CERT_PATH = os.path.join(CLOUDFLARED_HOME, "cert.pem")       # legacy shared cert (pre-1.3.0)
LEGACY_CERT = os.path.expanduser("~/.cloudflared/cert.pem")  # cloudflared's default output
CONFIG_PATH = os.path.join(CLOUDFLARED_HOME, "config.yml")
SERVICE_NAME = "cloudflared"


def _arch():
    m = (subprocess.run(["uname", "-m"], capture_output=True, text=True).stdout or "").strip()
    if m in ("x86_64", "amd64"):
        return "amd64"
    if m in ("aarch64", "arm64"):
        return "arm64"
    if m.startswith("arm"):
        return "arm"
    return "amd64"


def _cert_path_for(profile_id):
    return os.path.join(CLOUDFLARED_HOME, "cert-{}.pem".format(profile_id))


def _login_log_for(profile_id):
    return "/tmp/cloudflared_login_{}.log".format(profile_id or "default")


class TunnelManager:
    def __init__(self):
        self.plugin_dir = os.path.dirname(os.path.abspath(__file__))
        self.data_dir = os.path.join(self.plugin_dir, "data")
        if not os.path.exists(self.data_dir):
            os.makedirs(self.data_dir)
        if not os.path.exists(CLOUDFLARED_HOME):
            os.makedirs(CLOUDFLARED_HOME)
        self.state_file = os.path.join(self.data_dir, "state.json")

    # ---------- state ----------
    def _read_state(self):
        if not os.path.exists(self.state_file):
            return {"active_tunnel_id": "", "active_tunnel_name": "", "active_zone_id": "", "active_profile_id": ""}
        try:
            s = json.loads(public.readFile(self.state_file) or "{}")
        except Exception:
            s = {}
        # Backfill any fields older state files were missing.
        for k in ("active_tunnel_id", "active_tunnel_name", "active_zone_id", "active_profile_id"):
            s.setdefault(k, "")
        return s

    def _write_state(self, state):
        public.writeFile(self.state_file, json.dumps(state, indent=2))

    # ---------- status ----------
    def get_status(self, get):
        installed = os.path.exists(CLOUDFLARED_BIN)
        version = ""
        if installed:
            try:
                out = subprocess.run([CLOUDFLARED_BIN, "--version"], capture_output=True, text=True, timeout=5)
                version = (out.stdout or out.stderr).strip().splitlines()[0] if (out.stdout or out.stderr) else ""
            except Exception:
                version = ""

        # v1.3.0: "logged_in" is true when any profile has a cert on disk. The legacy
        # global cert.pem also counts so the UI can flag "needs migration".
        try:
            from dns_manager import DnsManager
            profiles = DnsManager()._all_profiles()
        except Exception:
            profiles = []
        any_logged_in = any(
            p.get("cert_path") and os.path.exists(p["cert_path"])
            for p in profiles
        ) or os.path.exists(CERT_PATH)

        # systemd service status
        svc_state = "unknown"
        svc_enabled = False
        try:
            r = subprocess.run(["systemctl", "is-active", SERVICE_NAME], capture_output=True, text=True, timeout=5)
            svc_state = (r.stdout or r.stderr).strip() or "unknown"
            r2 = subprocess.run(["systemctl", "is-enabled", SERVICE_NAME], capture_output=True, text=True, timeout=5)
            svc_enabled = (r2.stdout or "").strip() == "enabled"
        except Exception:
            pass

        state = self._read_state()
        return {
            "status": True,
            "data": {
                "installed": installed,
                "version": version,
                "logged_in": any_logged_in,
                "service_active": svc_state,
                "service_enabled": svc_enabled,
                "active_tunnel_id": state.get("active_tunnel_id", ""),
                "active_tunnel_name": state.get("active_tunnel_name", ""),
                "active_profile_id": state.get("active_profile_id", ""),
                "active_zone_id": state.get("active_zone_id", ""),
                "config_path": CONFIG_PATH,
                "legacy_cert_present": os.path.exists(CERT_PATH),
            },
        }

    # ---------- install / uninstall cloudflared ----------
    def install_cloudflared(self, get):
        if os.path.exists(CLOUDFLARED_BIN):
            return public.returnMsg(True, "cloudflared already installed")
        arch = _arch()
        url = "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-{}".format(arch)
        tmp = "/tmp/cloudflared.download"
        rc = os.system("curl -fsSL -o {} {}".format(tmp, url))
        if rc != 0 or not os.path.exists(tmp) or os.path.getsize(tmp) < 1024 * 1024:
            return public.returnMsg(False, "Download failed. Check outbound network to github.com.")
        os.system("install -m 0755 {} {}".format(tmp, CLOUDFLARED_BIN))
        os.remove(tmp)
        if not os.path.exists(CLOUDFLARED_BIN):
            return public.returnMsg(False, "Failed to install cloudflared binary")
        return public.returnMsg(True, "cloudflared installed")

    def uninstall_cloudflared(self, get):
        os.system("systemctl stop {} 2>/dev/null".format(SERVICE_NAME))
        os.system("systemctl disable {} 2>/dev/null".format(SERVICE_NAME))
        if os.path.exists(CLOUDFLARED_BIN):
            os.remove(CLOUDFLARED_BIN)
        return public.returnMsg(True, "cloudflared binary removed (config kept)")

    # ---------- login (browser flow, per-profile) ----------
    def _resolve_profile(self, get):
        """Load the profile referenced by get.profile_id. Kept small because both login
        endpoints need the same 'profile must exist and not be virtual' check."""
        from dns_manager import DnsManager
        pid = (get.profile_id or "").strip() if hasattr(get, "profile_id") else ""
        if not pid:
            return None, "profile_id required (v1.3.0: browser login is bound to a specific profile)"
        if pid.startswith("__"):
            return None, "Virtual profiles are DNS-only, they can't own a browser login. Add a regular profile first."
        profile = DnsManager().find_profile(pid)
        if not profile:
            return None, "Profile not found"
        return profile, None

    def cf_login_start(self, get):
        if not os.path.exists(CLOUDFLARED_BIN):
            return public.returnMsg(False, "Install cloudflared first")
        profile, err = self._resolve_profile(get)
        if err:
            return public.returnMsg(False, err)

        log = _login_log_for(profile["id"])
        # Kill any prior login (there can only be one active — cloudflared always writes to
        # ~/.cloudflared/cert.pem, we move it to the profile's slot after).
        os.system("pkill -f 'cloudflared tunnel login' 2>/dev/null")
        # Wipe the shared cert.pem source so the new login lands with a known-empty target.
        for p in (LEGACY_CERT, CERT_PATH):
            if os.path.exists(p):
                try: os.remove(p)
                except Exception: pass
        public.writeFile(log, "")
        os.system("nohup {} tunnel login > {} 2>&1 &".format(CLOUDFLARED_BIN, log))

        url = ""
        for _ in range(20):
            time.sleep(0.5)
            m = re.search(r"https://dash\.cloudflare\.com[^\s]+", public.readFile(log) or "")
            if m:
                url = m.group(0); break
        if not url:
            return public.returnMsg(False, "Could not capture the Cloudflare auth URL. See " + log)
        return {"status": True, "msg": "Open the URL and authorize a zone for '{}'.".format(profile["name"]), "data": {"url": url, "profile_id": profile["id"]}}

    def cf_login_status(self, get):
        profile, err = self._resolve_profile(get)
        if err:
            return public.returnMsg(False, err)
        target = _cert_path_for(profile["id"])

        # Look for the fresh cert.pem in the two paths cloudflared writes to and move it
        # onto the profile's slot. Idempotent: if the target already exists we just report.
        if not os.path.exists(target):
            for src in (LEGACY_CERT, CERT_PATH):
                if os.path.exists(src):
                    try:
                        os.makedirs(CLOUDFLARED_HOME, exist_ok=True)
                        os.rename(src, target)
                        os.chmod(target, 0o600)
                        break
                    except Exception:
                        pass
        ok = os.path.exists(target)
        if ok:
            from dns_manager import DnsManager
            DnsManager().set_profile_cert(profile["id"], target)
        return {"status": True, "msg": "ok" if ok else "waiting", "data": {"logged_in": ok, "profile_id": profile["id"]}}

    # ---------- tunnels ----------
    def _run_cf(self, args, cert_path=None, timeout=30):
        """Run cloudflared with TUNNEL_ORIGIN_CERT pointing at a specific cert.pem so the
        CLI operates on the right Cloudflare account. cert_path=None falls back to the
        legacy shared cert if present — useful for uninstall-service which is
        account-agnostic."""
        if not os.path.exists(CLOUDFLARED_BIN):
            return False, "cloudflared not installed"
        env = os.environ.copy()
        chosen = cert_path or (CERT_PATH if os.path.exists(CERT_PATH) else "")
        if chosen and os.path.exists(chosen):
            env["TUNNEL_ORIGIN_CERT"] = chosen
        try:
            r = subprocess.run([CLOUDFLARED_BIN] + args, capture_output=True, text=True, timeout=timeout, env=env)
            return r.returncode == 0, (r.stdout + r.stderr).strip()
        except subprocess.TimeoutExpired:
            return False, "cloudflared command timed out"
        except Exception as e:
            return False, str(e)

    def _logged_in_profiles(self):
        """Profiles that have a cert.pem on disk — these are the ones CLI ops can target."""
        from dns_manager import DnsManager
        out = []
        for p in DnsManager()._all_profiles():
            if p.get("virtual"):
                continue
            cp = p.get("cert_path")
            if cp and os.path.exists(cp):
                out.append(p)
        return out

    def list_tunnels(self, get):
        """Aggregate tunnels across every logged-in profile. Each row is tagged with the
        profile that owns it so the UI can render an Account column and prevent
        cross-account operations."""
        profiles = self._logged_in_profiles()
        errors = []
        rows = []
        for p in profiles:
            ok, out = self._run_cf(["tunnel", "list", "--output", "json"], cert_path=p["cert_path"])
            if not ok:
                errors.append("{}: {}".format(p["name"], out[:120]))
                continue
            try:
                tunnels = json.loads(out) or []
            except Exception:
                tunnels = []
            for t in tunnels:
                rows.append({
                    "id": t.get("id", ""),
                    "name": t.get("name", ""),
                    "created_at": t.get("created_at", ""),
                    "connections": len(t.get("connections", []) or []),
                    "profile_id": p["id"],
                    "profile_name": p["name"],
                })
        if not rows and not profiles:
            return {"status": False, "msg": "No profiles are logged in. Click 'Login' on a profile first.", "data": []}
        if not rows and errors:
            return {"status": False, "msg": "; ".join(errors), "data": []}
        return {"status": True, "msg": "ok", "data": rows}

    def create_tunnel(self, get):
        name = (get.tunnel_name or "").strip() if hasattr(get, "tunnel_name") else ""
        profile_id = (get.profile_id or "").strip() if hasattr(get, "profile_id") else ""
        if not name or not re.match(r"^[A-Za-z0-9_-]{1,63}$", name):
            return public.returnMsg(False, "Tunnel name must be 1-63 chars, A-Z a-z 0-9 _ -")
        if not profile_id:
            return public.returnMsg(False, "profile_id required — pick which account to create the tunnel in")
        from dns_manager import DnsManager
        profile = DnsManager().find_profile(profile_id)
        if not profile:
            return public.returnMsg(False, "Profile not found")
        cert = profile.get("cert_path")
        if not cert or not os.path.exists(cert):
            return public.returnMsg(False, "This profile isn't logged in yet — click Login on it first")

        ok, out = self._run_cf(["tunnel", "create", name], cert_path=cert, timeout=60)
        if not ok:
            return public.returnMsg(False, "Create failed: " + out)
        m = re.search(r"([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})", out)
        tid = m.group(1) if m else ""

        # cloudflared writes credentials to ~/.cloudflared/<id>.json by default; relocate.
        legacy_cred = os.path.expanduser("~/.cloudflared/{}.json".format(tid))
        target_cred = os.path.join(CLOUDFLARED_HOME, "{}.json".format(tid))
        if tid and os.path.exists(legacy_cred) and not os.path.exists(target_cred):
            try: os.rename(legacy_cred, target_cred)
            except Exception: pass
        return {"status": True, "msg": "Tunnel created in {}".format(profile["name"]), "data": {"id": tid, "name": name, "profile_id": profile["id"], "profile_name": profile["name"]}}

    def select_tunnel(self, get):
        # `id` fallback for stale-cached UIs — same pattern as v1.2.x.
        tid = ""
        if hasattr(get, "tunnel_id") and get.tunnel_id: tid = get.tunnel_id.strip()
        elif hasattr(get, "id") and get.id: tid = get.id.strip()
        name = (get.tunnel_name or "").strip() if hasattr(get, "tunnel_name") else ""
        profile_id = (get.profile_id or "").strip() if hasattr(get, "profile_id") else ""
        if not tid:
            return public.returnMsg(False, "Missing tunnel id")
        state = self._read_state()
        state["active_tunnel_id"] = tid
        state["active_tunnel_name"] = name
        if profile_id:
            state["active_profile_id"] = profile_id
        if hasattr(get, "zone_id") and get.zone_id:
            state["active_zone_id"] = get.zone_id
        self._write_state(state)
        return public.returnMsg(True, "Active tunnel set")

    def delete_tunnel(self, get):
        tid = ""
        if hasattr(get, "tunnel_id") and get.tunnel_id: tid = get.tunnel_id.strip()
        elif hasattr(get, "id") and get.id: tid = get.id.strip()
        profile_id = (get.profile_id or "").strip() if hasattr(get, "profile_id") else ""
        if not tid:
            return public.returnMsg(False, "Missing tunnel id")

        # Delete needs the account's cert. If the caller passed profile_id (new UI does),
        # use it directly. Otherwise try the active-tunnel's profile from state as a
        # convenience for legacy UIs.
        cert = None
        if profile_id:
            from dns_manager import DnsManager
            p = DnsManager().find_profile(profile_id)
            if p and p.get("cert_path"):
                cert = p["cert_path"]
        if not cert:
            state = self._read_state()
            if state.get("active_tunnel_id") == tid and state.get("active_profile_id"):
                from dns_manager import DnsManager
                p = DnsManager().find_profile(state["active_profile_id"])
                if p and p.get("cert_path"):
                    cert = p["cert_path"]

        self._run_cf(["tunnel", "cleanup", tid], cert_path=cert, timeout=20)
        ok, out = self._run_cf(["tunnel", "delete", "-f", tid], cert_path=cert, timeout=30)
        if not ok:
            return public.returnMsg(False, "Delete failed: " + out)
        cred = os.path.join(CLOUDFLARED_HOME, "{}.json".format(tid))
        if os.path.exists(cred):
            os.remove(cred)
        state = self._read_state()
        if state.get("active_tunnel_id") == tid:
            state["active_tunnel_id"] = ""
            state["active_tunnel_name"] = ""
            state["active_profile_id"] = ""
            self._write_state(state)
        return public.returnMsg(True, "Tunnel deleted")

    # ---------- service ----------
    def service_action(self, get):
        action = (get.act or "").strip() if hasattr(get, "act") else ""
        if action not in ("install", "uninstall", "start", "stop", "restart", "enable", "disable"):
            return public.returnMsg(False, "Unknown service action")

        if action == "install":
            if not os.path.exists(CONFIG_PATH):
                return public.returnMsg(False, "Write a config first (add at least one hostname)")
            ok, out = self._run_cf(["--config", CONFIG_PATH, "service", "install"], timeout=30)
            if not ok:
                return public.returnMsg(False, "Install failed: " + out)
            return public.returnMsg(True, "Service installed and started")

        if action == "uninstall":
            ok, out = self._run_cf(["service", "uninstall"], timeout=30)
            if not ok:
                return public.returnMsg(False, "Uninstall failed: " + out)
            return public.returnMsg(True, "Service uninstalled")

        rc = os.system("systemctl {} {} 2>&1".format(action, SERVICE_NAME))
        if rc != 0:
            return public.returnMsg(False, "systemctl {} returned non-zero".format(action))
        return public.returnMsg(True, "systemctl {} {} ok".format(action, SERVICE_NAME))

    def get_log(self, get):
        try:
            r = subprocess.run(
                ["journalctl", "-u", SERVICE_NAME, "-n", "200", "--no-pager"],
                capture_output=True, text=True, timeout=10,
            )
            log = (r.stdout or r.stderr or "").strip()
        except Exception as e:
            log = "Failed to read log: {}".format(e)
        return {"status": True, "msg": "ok", "data": {"log": log}}
