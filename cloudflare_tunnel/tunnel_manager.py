#!/usr/bin/python
# coding: utf-8
# Manages the cloudflared binary, login, tunnel CRUD, and the systemd service.

import json
import os
import re
import subprocess
import time

import public

CLOUDFLARED_BIN = "/usr/local/bin/cloudflared"
CLOUDFLARED_HOME = "/etc/cloudflared"
CERT_PATH = os.path.join(CLOUDFLARED_HOME, "cert.pem")
LEGACY_CERT = os.path.expanduser("~/.cloudflared/cert.pem")
CONFIG_PATH = os.path.join(CLOUDFLARED_HOME, "config.yml")
SERVICE_NAME = "cloudflared"
LOGIN_LOG = "/tmp/cloudflared_login.log"


def _arch():
    m = (subprocess.run(["uname", "-m"], capture_output=True, text=True).stdout or "").strip()
    if m in ("x86_64", "amd64"):
        return "amd64"
    if m in ("aarch64", "arm64"):
        return "arm64"
    if m.startswith("arm"):
        return "arm"
    return "amd64"


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
            return {"active_tunnel_id": "", "active_tunnel_name": "", "active_zone_id": ""}
        try:
            return json.loads(public.readFile(self.state_file) or "{}")
        except Exception:
            return {"active_tunnel_id": "", "active_tunnel_name": "", "active_zone_id": ""}

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

        logged_in = os.path.exists(CERT_PATH) or os.path.exists(LEGACY_CERT)

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
                "logged_in": logged_in,
                "service_active": svc_state,
                "service_enabled": svc_enabled,
                "active_tunnel_id": state.get("active_tunnel_id", ""),
                "active_tunnel_name": state.get("active_tunnel_name", ""),
                "active_zone_id": state.get("active_zone_id", ""),
                "config_path": CONFIG_PATH,
            },
        }

    # ---------- install / uninstall cloudflared ----------
    def install_cloudflared(self, get):
        if os.path.exists(CLOUDFLARED_BIN):
            return public.returnMsg(True, "cloudflared already installed")
        arch = _arch()
        url = "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-{}".format(arch)
        tmp = "/tmp/cloudflared.download"
        # curl is universally available on AAPanel hosts
        cmd = "curl -fsSL -o {} {}".format(tmp, url)
        rc = os.system(cmd)
        if rc != 0 or not os.path.exists(tmp) or os.path.getsize(tmp) < 1024 * 1024:
            return public.returnMsg(False, "Download failed. Check outbound network to github.com.")
        os.system("install -m 0755 {} {}".format(tmp, CLOUDFLARED_BIN))
        os.remove(tmp)
        if not os.path.exists(CLOUDFLARED_BIN):
            return public.returnMsg(False, "Failed to install cloudflared binary")
        return public.returnMsg(True, "cloudflared installed")

    def uninstall_cloudflared(self, get):
        # Stop service first so we don't leave orphaned processes.
        os.system("systemctl stop {} 2>/dev/null".format(SERVICE_NAME))
        os.system("systemctl disable {} 2>/dev/null".format(SERVICE_NAME))
        if os.path.exists(CLOUDFLARED_BIN):
            os.remove(CLOUDFLARED_BIN)
        return public.returnMsg(True, "cloudflared binary removed (config kept)")

    # ---------- login (browser flow) ----------
    def cf_login_start(self, get):
        if not os.path.exists(CLOUDFLARED_BIN):
            return public.returnMsg(False, "Install cloudflared first")
        # Kill any previous login waiter.
        os.system("pkill -f 'cloudflared tunnel login' 2>/dev/null")
        public.writeFile(LOGIN_LOG, "")
        # cloudflared writes the auth URL to stderr and then waits for the callback.
        # cert.pem lands at ~/.cloudflared/cert.pem; cf_login_status moves it to CERT_PATH.
        cmd = "nohup {} tunnel login > {} 2>&1 &".format(CLOUDFLARED_BIN, LOGIN_LOG)
        os.system(cmd)

        # Poll the log briefly for the URL.
        url = ""
        for _ in range(20):
            time.sleep(0.5)
            log = public.readFile(LOGIN_LOG) or ""
            m = re.search(r"https://dash\.cloudflare\.com[^\s]+", log)
            if m:
                url = m.group(0)
                break
        if not url:
            return public.returnMsg(False, "Could not capture the Cloudflare auth URL. See " + LOGIN_LOG)
        return {"status": True, "msg": "Open the URL and authorize a zone.", "data": {"url": url}}

    def cf_login_status(self, get):
        # Move legacy ~/.cloudflared/cert.pem into /etc/cloudflared so the systemd unit can find it.
        if not os.path.exists(CERT_PATH) and os.path.exists(LEGACY_CERT):
            try:
                os.makedirs(CLOUDFLARED_HOME, exist_ok=True)
                os.rename(LEGACY_CERT, CERT_PATH)
            except Exception:
                pass
        ok = os.path.exists(CERT_PATH)
        return {"status": True, "msg": "ok" if ok else "waiting", "data": {"logged_in": ok}}

    # ---------- tunnels ----------
    def _run_cf(self, args, timeout=30):
        if not os.path.exists(CLOUDFLARED_BIN):
            return False, "cloudflared not installed"
        env = os.environ.copy()
        env["TUNNEL_ORIGIN_CERT"] = CERT_PATH
        try:
            r = subprocess.run([CLOUDFLARED_BIN] + args, capture_output=True, text=True, timeout=timeout, env=env)
            return r.returncode == 0, (r.stdout + r.stderr).strip()
        except subprocess.TimeoutExpired:
            return False, "cloudflared command timed out"
        except Exception as e:
            return False, str(e)

    def list_tunnels(self, get):
        ok, out = self._run_cf(["tunnel", "list", "--output", "json"])
        if not ok:
            # Fall back: empty list with the error in msg so the UI can show "log in first".
            return {"status": False, "msg": out, "data": []}
        try:
            tunnels = json.loads(out) or []
        except Exception:
            tunnels = []
        # Trim to just the fields the UI cares about.
        slim = []
        for t in tunnels:
            slim.append({
                "id": t.get("id", ""),
                "name": t.get("name", ""),
                "created_at": t.get("created_at", ""),
                "connections": len(t.get("connections", []) or []),
            })
        return {"status": True, "msg": "ok", "data": slim}

    def create_tunnel(self, get):
        # Use tunnel_name (not `name`) so we don't collide with aaPanel's
        # `name=<plugin>` URL parameter on /plugin?action=a.
        name = (get.tunnel_name or "").strip() if hasattr(get, "tunnel_name") else ""
        if not name or not re.match(r"^[A-Za-z0-9_-]{1,63}$", name):
            return public.returnMsg(False, "Tunnel name must be 1-63 chars, A-Z a-z 0-9 _ -")
        ok, out = self._run_cf(["tunnel", "create", name], timeout=60)
        if not ok:
            return public.returnMsg(False, "Create failed: " + out)
        m = re.search(r"([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})", out)
        tid = m.group(1) if m else ""
        # cloudflared writes credentials to ~/.cloudflared/<id>.json by default; relocate.
        legacy_cred = os.path.expanduser("~/.cloudflared/{}.json".format(tid))
        target_cred = os.path.join(CLOUDFLARED_HOME, "{}.json".format(tid))
        if tid and os.path.exists(legacy_cred) and not os.path.exists(target_cred):
            try:
                os.rename(legacy_cred, target_cred)
            except Exception:
                pass
        return {"status": True, "msg": "Tunnel created", "data": {"id": tid, "name": name}}

    def select_tunnel(self, get):
        # `id` is accepted as a fallback so stale-cached UIs keep working.
        tid = ""
        if hasattr(get, "tunnel_id") and get.tunnel_id: tid = get.tunnel_id.strip()
        elif hasattr(get, "id") and get.id: tid = get.id.strip()
        name = (get.tunnel_name or "").strip() if hasattr(get, "tunnel_name") else ""
        if not tid:
            return public.returnMsg(False, "Missing tunnel id")
        state = self._read_state()
        state["active_tunnel_id"] = tid
        state["active_tunnel_name"] = name
        if hasattr(get, "zone_id") and get.zone_id:
            state["active_zone_id"] = get.zone_id
        self._write_state(state)
        return public.returnMsg(True, "Active tunnel set")

    def delete_tunnel(self, get):
        tid = ""
        if hasattr(get, "tunnel_id") and get.tunnel_id: tid = get.tunnel_id.strip()
        elif hasattr(get, "id") and get.id: tid = get.id.strip()
        if not tid:
            return public.returnMsg(False, "Missing tunnel id")
        # `cleanup` removes lingering connections so delete doesn't refuse.
        self._run_cf(["tunnel", "cleanup", tid], timeout=20)
        ok, out = self._run_cf(["tunnel", "delete", "-f", tid], timeout=30)
        if not ok:
            return public.returnMsg(False, "Delete failed: " + out)
        # Clean up creds + clear active state if it was this one.
        cred = os.path.join(CLOUDFLARED_HOME, "{}.json".format(tid))
        if os.path.exists(cred):
            os.remove(cred)
        state = self._read_state()
        if state.get("active_tunnel_id") == tid:
            state["active_tunnel_id"] = ""
            state["active_tunnel_name"] = ""
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
            # `cloudflared service install` creates the systemd unit and starts it.
            ok, out = self._run_cf(["--config", CONFIG_PATH, "service", "install"], timeout=30)
            if not ok:
                return public.returnMsg(False, "Install failed: " + out)
            return public.returnMsg(True, "Service installed and started")

        if action == "uninstall":
            ok, out = self._run_cf(["service", "uninstall"], timeout=30)
            if not ok:
                return public.returnMsg(False, "Uninstall failed: " + out)
            return public.returnMsg(True, "Service uninstalled")

        # plain systemctl actions
        rc = os.system("systemctl {} {} 2>&1".format(action, SERVICE_NAME))
        if rc != 0:
            return public.returnMsg(False, "systemctl {} returned non-zero".format(action))
        return public.returnMsg(True, "systemctl {} {} ok".format(action, SERVICE_NAME))

    def get_log(self, get):
        # journalctl is more reliable than tailing a file we don't own.
        try:
            r = subprocess.run(
                ["journalctl", "-u", SERVICE_NAME, "-n", "200", "--no-pager"],
                capture_output=True, text=True, timeout=10,
            )
            log = (r.stdout or r.stderr or "").strip()
        except Exception as e:
            log = "Failed to read log: {}".format(e)
        return {"status": True, "msg": "ok", "data": {"log": log}}
