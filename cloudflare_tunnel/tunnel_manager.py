#!/usr/bin/python
# coding: utf-8
# Manages the cloudflared binary, per-profile browser login, tunnel CRUD, and the
# systemd service. Every profile carries its own cert.pem so tunnel CRUD works across
# multiple Cloudflare accounts (v1.3.0).

import json
import base64
import shutil
import tempfile
import os
import re
import subprocess
import time

import public
from .storage import read_json, write_json, atomic_write, serialized, tunnel_uuid

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
    raise ValueError("Unsupported server architecture: " + m)


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
        return read_json(self.state_file, {})

    def _write_state(self, state):
        write_json(self.state_file, state)

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
            from .dns_manager import DnsManager
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
    @serialized
    def install_cloudflared(self, get):
        try:
            arch = _arch()
            url = "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-{}".format(arch)
            with tempfile.TemporaryDirectory(prefix="cft-install-") as directory:
                binary = os.path.join(directory, "cloudflared")
                result = subprocess.run(["curl", "--proto", "=https", "--proto-redir", "=https", "--tlsv1.2", "-fL", "--connect-timeout", "15", "--max-time", "180", "-o", binary, url], capture_output=True, text=True, timeout=190)
                if result.returncode or not os.path.exists(binary) or os.path.getsize(binary) < 1024 * 1024:
                    return public.returnMsg(False, "Download failed. Check outbound HTTPS to github.com. " + (result.stderr or "")[-400:])
                os.chmod(binary, 0o755)
                checked = subprocess.run([binary, "--version"], capture_output=True, text=True, timeout=10)
                if checked.returncode:
                    return public.returnMsg(False, "Downloaded binary failed its version check; installed binary kept")
                os.makedirs(os.path.dirname(CLOUDFLARED_BIN), exist_ok=True)
                fd, staging = tempfile.mkstemp(prefix=".cloudflared-", dir=os.path.dirname(CLOUDFLARED_BIN))
                os.close(fd)
                try:
                    shutil.copyfile(binary, staging)
                    os.chmod(staging, 0o755)
                    os.replace(staging, CLOUDFLARED_BIN)
                finally:
                    if os.path.exists(staging):
                        os.unlink(staging)
            return public.returnMsg(True, "cloudflared installed/updated: " + checked.stdout.strip() + ". Restart the service to use this binary.")
        except Exception as exc:
            return public.returnMsg(False, "Install/update failed: " + str(exc))

    @serialized
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
        from .dns_manager import DnsManager
        pid = (get.profile_id or "").strip() if hasattr(get, "profile_id") else ""
        if not pid:
            return None, "profile_id required (v1.3.0: browser login is bound to a specific profile)"
        if pid.startswith("__"):
            return None, "Virtual profiles are DNS-only, they can't own a browser login. Add a regular profile first."
        profile = DnsManager().find_profile(pid)
        if not profile:
            return None, "Profile not found"
        return profile, None

    @serialized
    def cf_login_start(self, get):
        if not os.path.exists(CLOUDFLARED_BIN):
            return public.returnMsg(False, "Install cloudflared first")
        profile, err = self._resolve_profile(get)
        if err:
            return public.returnMsg(False, err)

        # Each login runs with a private HOME, so cloudflared cannot overwrite or
        # accidentally attach another profile's certificate (including during re-login).
        session_file = os.path.join(self.data_dir, "login-{}.json".format(profile["id"]))
        previous = read_json(session_file, {})
        if previous and time.time() - previous.get("started", 0) < 300:
            if previous.get("url"):
                return {"status": True, "msg": "Continue browser login", "data": {"url": previous["url"], "profile_id": profile["id"]}}
            return public.returnMsg(False, "Login is starting. Retry shortly.")
        directory = tempfile.mkdtemp(prefix=".login-", dir=CLOUDFLARED_HOME)
        os.chmod(directory, 0o700)
        log = os.path.join(directory, "login.log")
        env = os.environ.copy()
        env["HOME"] = directory
        env.pop("TUNNEL_ORIGIN_CERT", None)
        with open(log, "w") as stream:
            os.chmod(log, 0o600)
            process = subprocess.Popen([CLOUDFLARED_BIN, "tunnel", "login"], env=env, cwd=directory, stdout=stream, stderr=subprocess.STDOUT, start_new_session=True)
        session = {"directory": directory, "started": time.time(), "pid": process.pid}
        write_json(session_file, session)
        url = ""
        for _ in range(20):
            time.sleep(0.5)
            match = re.search(r"https://dash\.cloudflare\.com[^\s]+", public.readFile(log) or "")
            if match:
                url = match.group(0)
                break
        if not url:
            return public.returnMsg(False, "Could not capture the Cloudflare login URL. Retry after five minutes; existing profile certificate was kept.")
        session["url"] = url
        write_json(session_file, session)
        return {"status": True, "msg": "Open the URL and authorize this account", "data": {"url": url, "profile_id": profile["id"]}}

    @serialized
    def cf_login_status(self, get):
        profile, err = self._resolve_profile(get)
        if err:
            return public.returnMsg(False, err)
        target = _cert_path_for(profile["id"])
        session_file = os.path.join(self.data_dir, "login-{}.json".format(profile["id"]))
        session = read_json(session_file, {})
        if session:
            fresh = os.path.join(session["directory"], ".cloudflared", "cert.pem")
            if not os.path.isfile(fresh) or os.path.getsize(fresh) == 0:
                return {"status": True, "msg": "waiting", "data": {"logged_in": False, "profile_id": profile["id"]}}
            try:
                atomic_write(target, public.readFile(fresh))
                from .dns_manager import DnsManager
                DnsManager().set_profile_cert(profile["id"], target)
                os.unlink(session_file)
                shutil.rmtree(session["directory"])
            except OSError as exc:
                return public.returnMsg(False, "Could not save login certificate: " + str(exc))
        ok = bool(profile.get("cert_path") and os.path.isfile(profile["cert_path"])) or os.path.isfile(target)
        if ok and not profile.get("cert_path") and os.path.isfile(target):
            from .dns_manager import DnsManager
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
        from .dns_manager import DnsManager
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
        from .dns_manager import DnsManager
        dns = DnsManager()
        profiles = dns._all_profiles()
        errors = []
        rows = []
        for p in profiles:
            if p.get("token") and p.get("account_id"):
                page = 1
                while True:
                    result = dns._request("GET", "/accounts/{}/cfd_tunnel".format(p["account_id"]), dns._auth_for_profile(p), p["name"], params={"is_deleted": "false", "per_page": 100, "page": page})
                    if not result["status"]:
                        errors.append(result["msg"] + ". Grant Account > Cloudflare Tunnel > Edit.")
                        break
                    tunnels = result["data"] or []
                    for tunnel in tunnels:
                        rows.append({"id": tunnel["id"], "name": tunnel.get("name", ""), "connections": len(tunnel.get("connections") or []), "profile_id": p["id"], "profile_name": p["name"], "remote": tunnel.get("config_src") == "cloudflare" or tunnel.get("remote_config", False)})
                    info = result.get("result_info") or {}
                    if page >= info.get("total_pages", page) or len(tunnels) < 100:
                        break
                    page += 1
                continue
            if not p.get("cert_path") or not os.path.exists(p["cert_path"]):
                continue
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
                    "remote": t.get("config_src") == "cloudflare" or t.get("remote_config", False),
                })
        if not rows and not profiles:
            return {"status": False, "msg": "No profiles are logged in. Click 'Login' on a profile first.", "data": []}
        if not rows and errors:
            return {"status": False, "msg": "; ".join(errors), "data": []}
        return {"status": True, "msg": "; ".join(errors) if errors else "ok", "data": rows, "warnings": errors}

    @serialized
    def create_tunnel(self, get):
        name = (get.tunnel_name or "").strip() if hasattr(get, "tunnel_name") else ""
        profile_id = (get.profile_id or "").strip() if hasattr(get, "profile_id") else ""
        if not name or not re.match(r"^[A-Za-z0-9_-]{1,63}$", name):
            return public.returnMsg(False, "Tunnel name must be 1-63 chars, A-Z a-z 0-9 _ -")
        if not profile_id:
            return public.returnMsg(False, "profile_id required — pick which account to create the tunnel in")
        from .dns_manager import DnsManager
        profile = DnsManager().find_profile(profile_id)
        if not profile:
            return public.returnMsg(False, "Profile not found")
        if profile.get("token") and profile.get("account_id"):
            dns = DnsManager()
            secret = base64.b64encode(os.urandom(32)).decode("ascii")
            result = dns._request("POST", "/accounts/{}/cfd_tunnel".format(profile["account_id"]), dns._auth_for_profile(profile), profile["name"], json={"name": name, "config_src": "local", "tunnel_secret": secret})
            if not result["status"]:
                return public.returnMsg(False, "Create failed: " + result["msg"] + ". Require Account > Cloudflare Tunnel > Edit. If the response was lost, check the dashboard before retrying.")
            tid = (result.get("data") or {}).get("id", "")
            try:
                tid = tunnel_uuid(tid)
                write_json(os.path.join(CLOUDFLARED_HOME, tid + ".json"), {"AccountTag": profile["account_id"], "TunnelID": tid, "TunnelSecret": secret})
            except Exception as exc:
                # The API may already have created the tunnel. Never lose that fact.
                return public.returnMsg(False, "Tunnel created ({}) but credentials could not be saved: {}. Remove it in Cloudflare before retrying.".format(tid, exc))
            return {"status": True, "msg": "Tunnel created using API token (no browser login needed)", "data": {"id": tid, "name": name, "profile_id": profile["id"], "profile_name": profile["name"]}}
        cert = profile.get("cert_path")
        if not cert or not os.path.exists(cert):
            return public.returnMsg(False, "This profile isn't logged in yet — click Login on it first")

        ok, out = self._run_cf(["tunnel", "create", name], cert_path=cert, timeout=60)
        if not ok:
            return public.returnMsg(False, "Create failed: " + out)
        m = re.search(r"([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})", out)
        tid = m.group(1) if m else ""

        if not tid:
            return public.returnMsg(False, "Tunnel creation returned no UUID; inspect Cloudflare before retrying")

        # cloudflared writes credentials to ~/.cloudflared/<id>.json by default; relocate.
        legacy_cred = os.path.expanduser("~/.cloudflared/{}.json".format(tid))
        target_cred = os.path.join(CLOUDFLARED_HOME, "{}.json".format(tid))
        if tid and os.path.exists(legacy_cred) and not os.path.exists(target_cred):
            try:
                os.rename(legacy_cred, target_cred)
            except OSError as exc:
                return public.returnMsg(False, "Tunnel created but credentials relocation failed: " + str(exc))
        if os.path.exists(target_cred):
            os.chmod(target_cred, 0o600)
        return {"status": True, "msg": "Tunnel created in {}".format(profile["name"]), "data": {"id": tid, "name": name, "profile_id": profile["id"], "profile_name": profile["name"]}}

    @serialized
    def select_tunnel(self, get):
        # `id` fallback for stale-cached UIs — same pattern as v1.2.x.
        tid = ""
        if hasattr(get, "tunnel_id") and get.tunnel_id: tid = get.tunnel_id.strip()
        elif hasattr(get, "id") and get.id: tid = get.id.strip()
        name = (get.tunnel_name or "").strip() if hasattr(get, "tunnel_name") else ""
        profile_id = (get.profile_id or "").strip() if hasattr(get, "profile_id") else ""
        try:
            tid = tunnel_uuid(tid)
        except ValueError as exc:
            return public.returnMsg(False, str(exc))
        listing = self.list_tunnels(get)
        selected = next((row for row in listing.get("data", []) if row["id"] == tid and (not profile_id or row["profile_id"] == profile_id)), None)
        if not selected:
            return public.returnMsg(False, "Tunnel unavailable in this account. " + listing.get("msg", ""))
        if selected.get("remote"):
            return public.returnMsg(False, "This tunnel is managed in Cloudflare. Manage its hostnames in the dashboard, or create a new local tunnel here.")
        profile_id = selected["profile_id"]
        name = selected["name"]
        state = self._read_state()
        previous_state = dict(state)
        if state.get("active_tunnel_id") and state["active_tunnel_id"] != tid:
            if read_json(os.path.join(self.data_dir, "ingress.json"), []):
                return public.returnMsg(False, "Remove current hostname rules before switching tunnels, so DNS cannot point to the previous tunnel")
        state["active_tunnel_id"] = tid
        state["active_tunnel_name"] = name
        state["active_profile_id"] = profile_id
        if hasattr(get, "zone_id") and get.zone_id:
            state["active_zone_id"] = get.zone_id
        self._write_state(state)
        from .ingress_manager import IngressManager
        result = IngressManager().apply_config(get)
        if not result.get("status"):
            self._write_state(previous_state)
            return public.returnMsg(False, "Tunnel setup failed; previous selection kept: " + result.get("msg", "") + ". Retry Use on the created tunnel.")
        return public.returnMsg(True, "Active tunnel set; configuration and service ready")

    @serialized
    def delete_tunnel(self, get):
        tid = ""
        if hasattr(get, "tunnel_id") and get.tunnel_id: tid = get.tunnel_id.strip()
        elif hasattr(get, "id") and get.id: tid = get.id.strip()
        profile_id = (get.profile_id or "").strip() if hasattr(get, "profile_id") else ""
        if not tid:
            return public.returnMsg(False, "Missing tunnel id")

        try:
            tid = tunnel_uuid(tid)
        except ValueError as exc:
            return public.returnMsg(False, str(exc))
        if self._read_state().get("active_tunnel_id") == tid:
            return public.returnMsg(False, "Cannot delete the active tunnel. Remove routes and select another tunnel first.")
        from .dns_manager import DnsManager
        dns = DnsManager()
        profile = dns.find_profile(profile_id)
        if not profile:
            return public.returnMsg(False, "Select the owning profile before deleting a tunnel")
        if profile.get("token") and profile.get("account_id"):
            result = dns._request("DELETE", "/accounts/{}/cfd_tunnel/{}".format(profile["account_id"], tid), dns._auth_for_profile(profile), profile["name"])
            if not result["status"]:
                return public.returnMsg(False, result["msg"])
            cred = os.path.join(CLOUDFLARED_HOME, tid + ".json")
            if os.path.exists(cred):
                os.unlink(cred)
            return public.returnMsg(True, "Tunnel deleted")
        # Delete needs the account's cert. If the caller passed profile_id (new UI does),
        # use it directly. Otherwise try the active-tunnel's profile from state as a
        # convenience for legacy UIs.
        cert = None
        if profile_id:
            from .dns_manager import DnsManager
            p = DnsManager().find_profile(profile_id)
            if p and p.get("cert_path"):
                cert = p["cert_path"]
        if not cert:
            state = self._read_state()
            if state.get("active_tunnel_id") == tid and state.get("active_profile_id"):
                from .dns_manager import DnsManager
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
    @serialized
    def service_action(self, get):
        action = (get.act or "").strip() if hasattr(get, "act") else ""
        if action not in ("install", "uninstall", "start", "stop", "restart", "enable", "disable"):
            return public.returnMsg(False, "Unknown service action")

        if action == "install":
            if not os.path.exists(CONFIG_PATH):
                from .ingress_manager import IngressManager
                return IngressManager().apply_config(get)
            ok, out = self._run_cf(["--config", CONFIG_PATH, "service", "install"], timeout=30)
            if not ok:
                return public.returnMsg(False, "Install failed: " + out)
            result = subprocess.run(["systemctl", "enable", "--now", SERVICE_NAME], capture_output=True, text=True, timeout=30)
            return public.returnMsg(result.returncode == 0, "Service installed and started" if result.returncode == 0 else "Service start failed: " + (result.stderr or result.stdout))

        if action == "uninstall":
            ok, out = self._run_cf(["service", "uninstall"], timeout=30)
            if not ok:
                return public.returnMsg(False, "Uninstall failed: " + out)
            return public.returnMsg(True, "Service uninstalled")

        result = subprocess.run(["systemctl", action, SERVICE_NAME], capture_output=True, text=True, timeout=30)
        if result.returncode != 0:
            return public.returnMsg(False, "systemctl {} failed: {}".format(action, result.stderr or result.stdout))
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
