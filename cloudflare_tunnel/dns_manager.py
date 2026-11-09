#!/usr/bin/python
# coding: utf-8
# Cloudflare API helpers: multi-profile credential storage, zone lookup, CNAME upsert.
#
# Multi-account (v1.2.0):
#   Users can register several profiles (e.g. Personal + Work), each with its own
#   API token. When adding a hostname, the plugin auto-picks the profile whose zone
#   matches — no manual account switcher needed.
#
# Credential precedence (highest first):
#   1) Persisted profiles in data/api_profiles.json (list of {id, name, token})
#   2) Virtual profile from cloudflare_manage plugin's cf_default.json
#   3) Virtual profile from AAPanel DNS manager (config/dns_mager.conf)
#
# A single 'default' persisted profile is auto-migrated from the legacy
# data/api_token.json on first load.

import hashlib
import base64
import json
import os
import re
import shutil
import time

import requests
import public
from .storage import read_json, write_json, serialized, mutation_lock

CF_API = "https://api.cloudflare.com/client/v4"
GLOBAL_CF_DEFAULT = "/www/server/panel/plugin/cloudflare_manage/data/cf_default.json"
GLOBAL_DNS_MAGER = "/www/server/panel/config/dns_mager.conf"

# cloudflared paths — per-profile cert.pem lives alongside the legacy global one.
CLOUDFLARED_HOME = "/etc/cloudflared"
LEGACY_GLOBAL_CERT = os.path.join(CLOUDFLARED_HOME, "cert.pem")


def _cert_path_for(profile_id):
    return os.path.join(CLOUDFLARED_HOME, "cert-{}.pem".format(profile_id))

# Short in-process cache for per-profile zone listings. Adding/removing a hostname
# is user-driven and infrequent — a 60s cache is enough to avoid hammering the API
# while still picking up new zones quickly.
_ZONES_CACHE_TTL = 60


class DnsManager:
    _zones_cache = {}  # profile_id -> {"at": ts, "zones": [...]}

    def __init__(self):
        self.plugin_dir = os.path.dirname(os.path.abspath(__file__))
        self.data_dir = os.path.join(self.plugin_dir, "data")
        if not os.path.exists(self.data_dir):
            os.makedirs(self.data_dir)
        self.legacy_token_file = os.path.join(self.data_dir, "api_token.json")
        self.profiles_file = os.path.join(self.data_dir, "api_profiles.json")
        with mutation_lock(self.data_dir):
            self._migrate_legacy_token()
            self._migrate_global_cert()

    # ---------- persistence ----------
    def _migrate_legacy_token(self):
        """One-shot: turn v1.1.x single-token storage into a profile named 'default'."""
        if os.path.exists(self.profiles_file) or not os.path.exists(self.legacy_token_file):
            return
        try:
            tok = json.loads(public.readFile(self.legacy_token_file) or "{}").get("token", "")
        except Exception:
            tok = ""
        if tok:
            self._write_profiles([{"id": self._new_id("default"), "name": "default", "token": tok}])
        # Remove the legacy file so migration doesn't run again.
        try: os.remove(self.legacy_token_file)
        except Exception: pass

    def _migrate_global_cert(self):
        """v1.3.0: move the pre-existing shared /etc/cloudflared/cert.pem onto a specific
        profile. Only auto-migrates when we can do it unambiguously — otherwise leaves
        the legacy file in place so the user can associate it manually via the UI."""
        if not os.path.exists(LEGACY_GLOBAL_CERT):
            return
        profiles = self._read_profiles()

        # Unambiguous: exactly one profile with no cert of its own — inherit the legacy cert.
        no_cert = [p for p in profiles if not p.get("cert_path")]
        if len(profiles) == 1 and len(no_cert) == 1:
            p = no_cert[0]
            target = _cert_path_for(p["id"])
            try:
                shutil.move(LEGACY_GLOBAL_CERT, target)
                os.chmod(target, 0o600)
                p["cert_path"] = target
                self._write_profiles(profiles)
            except Exception:
                pass
            return

        # No profiles at all — create a placeholder that owns the cert. User still has to
        # add a token to make it fully usable (label makes that obvious).
        if not profiles:
            pid = self._new_id("legacy")
            target = _cert_path_for(pid)
            try:
                shutil.move(LEGACY_GLOBAL_CERT, target)
                os.chmod(target, 0o600)
            except Exception:
                return
            self._write_profiles([{"id": pid, "name": "legacy (add token)", "token": "", "cert_path": target}])
            return

        # Ambiguous (multiple profiles without cert, or all already have certs) — leave
        # the legacy file alone. UI surfaces it as an unassigned-cert warning.

    def _read_profiles(self):
        return read_json(self.profiles_file, [])

    def _write_profiles(self, profiles):
        write_json(self.profiles_file, profiles)

    @staticmethod
    def _new_id(name):
        # Stable-ish id: name + a short hash so IDs stay readable in logs and the UI.
        h = hashlib.sha1(("{}:{}".format(name, time.time())).encode()).hexdigest()[:6]
        safe = "".join(c if c.isalnum() else "_" for c in (name or "profile"))[:12]
        return "{}_{}".format(safe or "p", h)

    @staticmethod
    def _read_json(path):
        if not os.path.exists(path):
            return None
        try:
            raw = public.readFile(path)
            if not raw or not raw.strip():
                return None
            return json.loads(raw)
        except Exception:
            return None

    # ---------- profile enumeration ----------
    def _all_profiles(self):
        """Return a list of profile dicts covering user-added + virtual (global) ones.
        Each entry has: id, name, virtual (bool), token (may be empty for login-only),
        cert_path (may be empty), and virtual profiles carry 'auth' headers instead.
        Virtual profiles never have cert_path — they're DNS-API-only."""
        profiles = []
        for p in self._read_profiles():
            if not isinstance(p, dict) or not p.get("id"):
                continue
            # v1.3.0: token is optional (a profile can be login-only, cert-only, or both).
            if not p.get("token") and not p.get("cert_path"):
                continue  # empty stub — hide it
            profiles.append({
                "id": p["id"],
                "name": p.get("name") or p["id"],
                "token": p.get("token", ""),
                "cert_path": p.get("cert_path", ""),
                "account_id": p.get("account_id", ""),
                "virtual": False,
            })

        # cloudflare_manage default
        cfg = self._read_json(GLOBAL_CF_DEFAULT)
        if cfg:
            auth = self._auth_from_cfg(cfg)
            if auth:
                profiles.append({"id": "__cloudflare_manage__", "name": "cloudflare_manage default", "auth": auth, "virtual": True})

        # aaPanel DNS manager
        dm = self._read_json(GLOBAL_DNS_MAGER)
        if dm and isinstance(dm, dict):
            for idx, c in enumerate(dm.get("CloudFlareDns") or []):
                auth = self._auth_from_cfg(c)
                if auth:
                    profiles.append({
                        "id": "__dns_mager_{}__".format(idx),
                        "name": "AAPanel DNS manager #{}".format(idx),
                        "auth": auth, "virtual": True,
                    })
        return profiles

    def find_profile(self, profile_id):
        """Look up a single profile by id — used by tunnel_manager for per-profile
        cert.pem resolution. Returns None if not found."""
        for p in self._read_profiles():
            if isinstance(p, dict) and p.get("id") == profile_id:
                return dict(p, virtual=False)
        for p in self._all_profiles():
            if p["id"] == profile_id:
                return p
        return None

    @serialized
    def set_profile_cert(self, profile_id, cert_path):
        """Persist that this profile just completed a browser login. No-op for virtual
        profiles (which don't have persistent state on our side)."""
        if profile_id.startswith("__"):
            return False
        profiles = self._read_profiles()
        for p in profiles:
            if p.get("id") == profile_id:
                p["cert_path"] = cert_path
                self._write_profiles(profiles)
                return True
        return False

    @staticmethod
    def _auth_from_cfg(cfg):
        """Extract auth headers from a cloudflare_manage / dns_mager config dict."""
        if not isinstance(cfg, dict):
            return None
        token = cfg.get("API Token") or cfg.get("api_token")
        if token:
            return {"Authorization": "Bearer " + token}
        email = cfg.get("E-Mail") or cfg.get("email")
        key = cfg.get("API Key") or cfg.get("api_key")
        if email and key:
            return {"X-Auth-Email": email, "X-Auth-Key": key}
        return None

    @staticmethod
    def _auth_for_profile(profile):
        if "auth" in profile:
            return profile["auth"]
        token = profile.get("token")
        return {"Authorization": "Bearer " + token} if token else None

    # ---------- profile CRUD (public endpoints) ----------
    def list_profiles(self, get):
        """UI listing: show ALL persisted profiles (even empty stubs the user is about to
        configure) plus every virtual one. Internal credential lookup still filters
        empty stubs out via _all_profiles(); this endpoint is UI-only."""
        out = []
        for p in self._read_profiles():
            if not isinstance(p, dict) or not p.get("id"):
                continue
            tok = p.get("token", "")
            cert_path = p.get("cert_path", "")
            login_pending = os.path.isfile(os.path.join(self.data_dir, "login-{}.json".format(p["id"])))
            out.append({
                "id": p["id"],
                "name": p.get("name") or p["id"],
                "virtual": False,
                "tail": tok[-4:] if tok else "",
                "has_token": bool(tok),
                "logged_in": bool(cert_path and os.path.exists(cert_path)) and not login_pending,
                "login_pending": login_pending,
                "cert_path": cert_path,
                "account_id": p.get("account_id", ""),
                "account_name": p.get("account_name", ""),
                "account_selected": bool(p.get("account_id")) and p.get("account_confirmed", True),
                "can_manage_tunnels": bool(tok and p.get("account_id")) or bool(cert_path and os.path.exists(cert_path)),
            })
        # Virtual profiles (cloudflare_manage / dns_mager) come from _all_profiles.
        for p in self._all_profiles():
            if not p.get("virtual"):
                continue
            out.append({
                "id": p["id"], "name": p["name"], "virtual": True,
                "tail": "", "has_token": True, "logged_in": False, "cert_path": "",
            })
        return {"status": True, "msg": "ok", "data": out}

    @serialized
    def add_profile(self, get):
        # `profile_name` (not `name`) avoids the aaPanel plugin-id URL-param collision.
        name = ((get.name_ if hasattr(get, "name_") else "") or (get.profile_name if hasattr(get, "profile_name") else "")).strip()
        token = (get.token or "").strip() if hasattr(get, "token") else ""
        if not name:
            return public.returnMsg(False, "Profile name required")
        account_id = (getattr(get, "account_id", "") or "").strip()
        if account_id and not re.fullmatch(r"[a-fA-F0-9]{32}", account_id):
            return public.returnMsg(False, "Account ID must contain 32 hexadecimal characters")
        warning = ""
        if token:
            ok, account_id, warning = self._inspect_token(token, account_id)
            if not ok:
                return public.returnMsg(False, warning)

        profiles = self._read_profiles()
        if any(p.get("name") == name for p in profiles):
            return public.returnMsg(False, "A profile with that name already exists")
        if token and any(p.get("token") == token for p in profiles):
            return public.returnMsg(False, "This token is already registered under another profile")

        pid = self._new_id(name)
        profiles.append({"id": pid, "name": name, "token": token, "cert_path": "", "account_id": account_id})
        self._write_profiles(profiles)
        DnsManager._zones_cache.clear()
        return {"status": True, "msg": "Profile added" + (". " + warning if warning else ""), "data": {"id": pid, "name": name}}

    @serialized
    def update_profile_token(self, get):
        """Attach or replace an API token on an existing profile without touching cert.
        Useful for the 'legacy (add token)' migrated profile, or to rotate keys."""
        pid = (get.profile_id or "").strip() if hasattr(get, "profile_id") else ""
        token = (get.token or "").strip() if hasattr(get, "token") else ""
        if not pid or pid.startswith("__"):
            return public.returnMsg(False, "profile_id required (virtual profiles can't be edited)")
        if not token or len(token) < 20:
            return public.returnMsg(False, "Token looks invalid")
        profile = self.find_profile(pid)
        if not profile:
            return public.returnMsg(False, "Profile not found")
        ok, account_id, warning = self._inspect_token(token, profile.get("account_id", ""))
        if not ok:
            return public.returnMsg(False, warning)
        profiles = self._read_profiles()
        for p in profiles:
            if p.get("id") == pid:
                p["token"] = token
                p["account_id"] = account_id
                p["account_confirmed"] = False
                self._write_profiles(profiles)
                DnsManager._zones_cache.clear()
                return public.returnMsg(True, "Token updated" + (". " + warning if warning else ""))
        return public.returnMsg(False, "Profile not found")

    @staticmethod
    def _browser_account(profile):
        """Read only the account identifier from cloudflared's private login cert."""
        path = profile.get("cert_path", "")
        if not path or not os.path.isfile(path):
            return ""
        try:
            text = public.readFile(path) or ""
            match = re.search(r"-----BEGIN ARGO TUNNEL TOKEN-----\s*(.*?)\s*-----END ARGO TUNNEL TOKEN-----", text, re.S)
            if not match:
                return ""
            payload = json.loads(base64.b64decode(re.sub(r"\s+", "", match.group(1)), validate=True))
            account_id = payload.get("accountID", "")
            return account_id if re.fullmatch(r"[a-fA-F0-9]{32}", account_id) else ""
        except (OSError, ValueError, TypeError):
            return ""

    def list_accounts(self, get):
        profile = self.find_profile((getattr(get, "profile_id", "") or "").strip())
        if not profile or profile.get("virtual"):
            return {"status": False, "msg": "Choose a connection first.", "data": []}
        pending = os.path.isfile(os.path.join(self.data_dir, "login-{}.json".format(profile["id"])))
        if pending or not profile.get("cert_path") or not os.path.isfile(profile["cert_path"]):
            return {"status": False, "msg": "Complete Browser login first.", "data": []}
        if not profile.get("token"):
            return {"status": False, "msg": "Save your API token first.", "data": []}
        auth = self._auth_for_profile(profile)
        accounts, errors = {}, []
        page = 1
        while True:
            result = self._request("GET", "/accounts", auth, profile["name"], params={"per_page": 50, "page": page})
            if not result["status"]:
                if accounts:
                    return {"status": False, "msg": "Could not finish loading accounts. Please refresh and retry.", "detail": result["msg"], "data": []}
                errors.append(result["msg"])
                break
            chunk = result["data"] or []
            for account in chunk:
                accounts[account["id"]] = {"id": account["id"], "name": account.get("name") or account["id"]}
            pages = (result.get("result_info") or {}).get("total_pages")
            if (pages is not None and page >= pages) or (pages is None and len(chunk) < 50):
                break
            page += 1
            if page > 10000:
                return {"status": False, "msg": "Too many account pages; restrict token resources and retry.", "data": []}
        # Tokens created with older templates may not list accounts. Zone metadata
        # and the login certificate supply IDs without requiring manual input.
        if not accounts:
            try:
                for zone in self._list_zones_for_profile(profile, refresh=True):
                    account_id = zone.get("account_id")
                    if account_id:
                        accounts[account_id] = {"id": account_id, "name": zone.get("account_name") or "Account for " + zone["name"]}
            except ValueError as exc:
                errors.append(str(exc))
        if not accounts:
            account_id = self._browser_account(profile)
            if account_id:
                result = self._request("GET", "/accounts/{}/cfd_tunnel".format(account_id), auth, profile["name"], params={"per_page": 1, "is_deleted": "false"})
                if result["status"]:
                    accounts[account_id] = {"id": account_id, "name": "Browser login account"}
                else:
                    errors.append(result["msg"])
        if not accounts:
            return {"status": False, "msg": "Could not load accounts. Create a new token using the button in step 2, then retry.", "detail": "; ".join(errors), "data": []}
        rows = list(accounts.values())
        return {"status": True, "msg": "ok", "data": rows}

    @serialized
    def select_account(self, get):
        pid = (getattr(get, "profile_id", "") or "").strip()
        account_id = (getattr(get, "account_id", "") or "").strip()
        listing = self.list_accounts(get)
        if not listing["status"]:
            return listing
        selected = next((row for row in listing["data"] if row["id"] == account_id), None)
        if selected is None:
            return public.returnMsg(False, "This account is no longer available. Refresh accounts and choose again.")
        result = self.update_profile_account(get)
        if not result.get("status"):
            return result
        profiles = self._read_profiles()
        for profile in profiles:
            if profile.get("id") == pid:
                profile["account_name"] = selected["name"]
                profile["account_confirmed"] = True
        self._write_profiles(profiles)
        return public.returnMsg(True, "Account selected")

    @serialized
    def update_profile_account(self, get):
        pid = (getattr(get, "profile_id", "") or "").strip()
        account_id = (getattr(get, "account_id", "") or "").strip()
        if not re.fullmatch(r"[a-fA-F0-9]{32}", account_id):
            return public.returnMsg(False, "Account ID must contain 32 hexadecimal characters")
        profiles = self._read_profiles()
        profile = next((p for p in profiles if p.get("id") == pid), None)
        if not profile:
            return public.returnMsg(False, "Profile not found")
        if profile.get("account_id") and profile["account_id"] != account_id:
            state = read_json(os.path.join(self.data_dir, "state.json"), {})
            if state.get("active_profile_id") == pid:
                return public.returnMsg(False, "Cannot change the account of an active tunnel's profile; create a separate profile")
        result = self._request("GET", "/accounts/{}/cfd_tunnel".format(account_id), self._auth_for_profile(profile), profile["name"], params={"per_page": 1, "is_deleted": "false"})
        if not result["status"]:
            return public.returnMsg(False, "Cannot access tunnels in this account: " + result["msg"] + ". Check Account ID and Cloudflare Tunnel Edit permission.")
        profile["account_id"] = account_id
        self._write_profiles(profiles)
        return public.returnMsg(True, "Account ID saved; API tunnel access verified")

    @serialized
    def delete_profile(self, get):
        pid = (get.profile_id or "").strip() if hasattr(get, "profile_id") else ""
        if not pid:
            return public.returnMsg(False, "profile_id required")
        if pid.startswith("__"):
            return public.returnMsg(False, "Virtual profiles come from cloudflare_manage / DNS manager and cannot be deleted here")
        profiles = self._read_profiles()
        removed = next((p for p in profiles if p.get("id") == pid), None)
        new = [p for p in profiles if p.get("id") != pid]
        if len(new) == len(profiles):
            return public.returnMsg(False, "Profile not found")
        state = read_json(os.path.join(self.data_dir, "state.json"), {})
        ingress = read_json(os.path.join(self.data_dir, "ingress.json"), [])
        if state.get("active_profile_id") == pid or any(i.get("dns_profile_id") == pid for i in ingress):
            return public.returnMsg(False, "Profile is in use by the active tunnel or DNS routes. Remove those references first.")
        # Clean the associated cert.pem too — orphan files pile up otherwise.
        if removed and removed.get("cert_path"):
            try: os.remove(removed["cert_path"])
            except Exception: pass
        self._write_profiles(new)
        DnsManager._zones_cache.clear()
        return public.returnMsg(True, "Profile removed")

    # ---------- back-compat convenience API (older UI still calls these) ----------
    @serialized
    def set_api_token(self, get):
        """Legacy single-token setter — creates/updates a profile called 'default'."""
        token = (get.token or "").strip() if hasattr(get, "token") else ""
        if not token or len(token) < 20:
            return public.returnMsg(False, "Token looks invalid")
        profiles = self._read_profiles()
        default = next((p for p in profiles if p.get("name") == "default"), None)
        if default:
            from types import SimpleNamespace
            return self.update_profile_token(SimpleNamespace(profile_id=default["id"], token=token))
        from types import SimpleNamespace
        return self.add_profile(SimpleNamespace(profile_name="default", token=token))

    @serialized
    def clear_api_token(self, get):
        """Legacy: removes the 'default' profile if one exists."""
        profiles = self._read_profiles()
        default = next((p for p in profiles if p.get("name") == "default"), None)
        if default:
            from types import SimpleNamespace
            return self.delete_profile(SimpleNamespace(profile_id=default["id"]))
        return public.returnMsg(True, "Default profile removed")

    def get_api_token_state(self, get):
        profiles = [p for p in self._all_profiles() if self._auth_for_profile(p)]
        persisted = [p for p in profiles if not p.get("virtual")]
        virtual = [p for p in profiles if p.get("virtual")]
        first_virtual = virtual[0]["name"] if virtual else ""
        return {
            "status": True, "msg": "ok",
            "data": {
                "profile_count": len(persisted),
                "virtual_count": len(virtual),
                "fallback_source": first_virtual,
                "any_creds": bool(profiles),
                # legacy fields for older UI:
                "present": len(persisted) > 0,
                "tail": persisted[0]["token"][-4:] if persisted else "",
            },
        }

    # ---------- API request (per-profile) ----------
    def _request(self, method, path, auth, source_label="", **kwargs):
        if not auth:
            return {"status": False, "msg": "No DNS API token on this profile. Browser login alone cannot list zones.", "data": None}
        headers = dict(kwargs.pop("headers", {}) or {})
        headers.update(auth)
        headers.setdefault("Content-Type", "application/json")
        kwargs.setdefault("timeout", 30)
        try:
            response = requests.request(method, CF_API + path, headers=headers, **kwargs)
            try:
                payload = response.json()
            except ValueError:
                return {"status": False, "msg": "Cloudflare returned HTTP {} with a non-JSON response".format(response.status_code), "data": None}
            if not isinstance(payload, dict):
                raise ValueError("Unexpected Cloudflare response")
        except Exception as exc:
            return {"status": False, "msg": "Cloudflare request failed: " + str(exc), "data": None}
        if not response.ok or not payload.get("success"):
            errors = payload.get("errors") or []
            message = "; ".join("{}: {}".format(e.get("code", "API"), e.get("message", "API error")) for e in errors)
            message = "HTTP {}: {}".format(response.status_code, message or "Cloudflare API error")
            if source_label:
                message += " (via {})".format(source_label)
            return {"status": False, "msg": message, "data": None}
        return {"status": True, "msg": "ok", "data": payload.get("result"), "result_info": payload.get("result_info") or {}}

    def _inspect_token(self, token, account_id=""):
        if len(token) < 20 or any(c.isspace() for c in token):
            return False, account_id, "Paste an API token, not a cloudflared command or Tunnel connector token"
        profile = {"id": "probe", "name": "new token", "token": token, "account_id": account_id}
        verify_path = "/accounts/{}/tokens/verify".format(account_id) if account_id else "/user/tokens/verify"
        verified = self._request("GET", verify_path, self._auth_for_profile(profile))
        if verified["status"] and (verified.get("data") or {}).get("status") != "active":
            return False, account_id, "API token is not active"
        zones = self._request("GET", "/zones", self._auth_for_profile(profile), params={"per_page": 50})
        if not verified["status"] and not zones["status"]:
            return False, account_id, "Token could not be verified. " + verified["msg"] + ". " + zones["msg"]
        accounts = {z.get("account", {}).get("id") for z in (zones.get("data") or [])} if zones["status"] else set()
        accounts.discard(None)
        # Only infer if the complete result fits on one page and has exactly one account.
        info = zones.get("result_info") or {}
        if not account_id and len(accounts) == 1 and len(zones["data"]) < 50 and info.get("total_pages", 1) <= 1:
            account_id = next(iter(accounts))
        warning = ""
        if not zones["status"]:
            warning = "Zone discovery failed: " + zones["msg"] + ". Grant Zone > Zone > Read and include the target zones."
        elif not zones["data"]:
            warning = "No accessible zones. Check token resource scope and Zone > Zone > Read. Manual DNS is still available."
        return True, account_id, warning.strip()

    # ---------- zones ----------
    def _list_zones_for_profile(self, profile, refresh=False):
        auth = self._auth_for_profile(profile)
        if not auth:
            return []
        key = (profile["id"], hashlib.sha256(json.dumps(auth, sort_keys=True).encode()).hexdigest())
        entry = DnsManager._zones_cache.get(key)
        if not refresh and entry and time.time() - entry["at"] < _ZONES_CACHE_TTL:
            return entry["zones"]
        zones = []
        page = 1
        while True:
            result = self._request("GET", "/zones", auth, profile["name"], params={"per_page": 50, "page": page})
            if not result["status"]:
                raise ValueError(result["msg"] + ". Require Zone > Zone > Read; include the intended zone in token resources.")
            chunk = result["data"] or []
            zones.extend({"id": z["id"], "name": z["name"], "status": z.get("status"), "account_id": (z.get("account") or {}).get("id", ""), "account_name": (z.get("account") or {}).get("name", "")} for z in chunk)
            pages = result["result_info"].get("total_pages")
            if (pages is not None and page >= pages) or (pages is None and len(chunk) < 50):
                break
            page += 1
            if page > 10000:
                raise ValueError("Zone pagination exceeded safety limit; narrow token resource scope")
        DnsManager._zones_cache[key] = {"at": time.time(), "zones": zones}
        return zones

    def list_zones(self, get):
        out, errors, seen = [], [], set()
        pid = (getattr(get, "profile_id", "") or "").strip()
        profiles = [p for p in self._all_profiles() if self._auth_for_profile(p) and (not pid or p["id"] == pid)]
        selected_account = (self.find_profile(pid) or {}).get("account_id", "") if pid else ""
        refresh = str(getattr(get, "refresh", "0")).lower() in ("1", "true")
        for profile in profiles:
            try:
                zones = self._list_zones_for_profile(profile, refresh=refresh)
            except ValueError as exc:
                errors.append(str(exc))
                continue
            for zone in zones:
                if selected_account and zone.get("account_id") != selected_account:
                    continue
                if zone["id"] in seen:
                    continue
                seen.add(zone["id"])
                out.append(dict(zone, profile_id=profile["id"], profile_name=profile["name"]))
        if not profiles:
            errors.append("No DNS API credentials. Add an API token with Zone Read and DNS Edit, or use manual DNS.")
        if not out and not errors:
            errors.append("No accessible zones. Check Zone Read permission and the token's zone resource scope, or use manual DNS.")
        return {"status": bool(out), "msg": "; ".join(errors) if errors else "ok", "data": out, "warnings": errors}

    def _resolve_zone_for_host(self, hostname, zone_id_hint="", profile_id="", account_id=""):
        best, errors = None, []
        for profile in self._all_profiles():
            if profile_id and profile["id"] != profile_id:
                continue
            if not self._auth_for_profile(profile):
                continue
            try:
                zones = self._list_zones_for_profile(profile)
            except ValueError as exc:
                errors.append(str(exc))
                continue
            for zone in zones:
                if zone_id_hint and zone["id"] != zone_id_hint:
                    continue
                if account_id and zone.get("account_id") != account_id:
                    continue
                name = zone["name"].lower().rstrip(".")
                if hostname == name or hostname.endswith("." + name):
                    if best is None or len(name) > len(best[1]["name"]):
                        best = (profile, zone)
        if best:
            return best[0], best[1]["id"], None
        message = "Selected zone is unavailable or does not match {}" if zone_id_hint else "No accessible Cloudflare zone matches {}"
        return None, None, message.format(hostname) + (". " + "; ".join(errors) if errors else ". Check Zone Read and token resources, or choose manual DNS.")

    def _records(self, profile, zone_id, hostname):
        result = self._request("GET", "/zones/{}/dns_records".format(zone_id), self._auth_for_profile(profile), profile["name"], params={"name": hostname, "per_page": 100})
        if not result["status"]:
            raise ValueError(result["msg"] + ". Require Zone > DNS > Edit for DNS automation.")
        if result.get("result_info", {}).get("total_pages", 1) > 1:
            raise ValueError("Too many DNS records at this hostname; review them manually")
        return result["data"] or []

    def prepare_cname(self, hostname, target, zone_id="", proxied=True, profile_id="", account_id=""):
        profile, zone_id, error = self._resolve_zone_for_host(hostname, zone_id, profile_id, account_id)
        if error:
            raise ValueError(error)
        records = self._records(profile, zone_id, hostname)
        if len(records) > 1 or any(r.get("type") != "CNAME" for r in records):
            raise ValueError("DNS conflict: existing non-CNAME or multiple records. Review DNS manually; nothing was overwritten.")
        previous = records[0] if records else None
        if previous and previous.get("content", "").lower().rstrip(".") != target.lower().rstrip("."):
            raise ValueError("DNS conflict: this CNAME points elsewhere. Review it manually; nothing was overwritten.")
        return {"profile_id": profile["id"], "zone_id": zone_id, "hostname": hostname,
                "previous": previous, "record_id": previous["id"] if previous else "",
                "body": {"type": "CNAME", "name": hostname, "content": target, "proxied": bool(proxied), "ttl": 1}}

    def commit_cname(self, change):
        profile = self.find_profile(change["profile_id"])
        path = "/zones/{}/dns_records".format(change["zone_id"])
        if change["record_id"]:
            path += "/" + change["record_id"]
        result = self._request("PATCH" if change["record_id"] else "POST", path, self._auth_for_profile(profile), profile["name"], json=change["body"])
        if not result["status"]:
            raise ValueError(result["msg"] + ". DNS write may have completed if the response was lost; inspect Cloudflare DNS before retrying.")
        change["record_id"] = (result.get("data") or {}).get("id") or change["record_id"]
        if not change["record_id"]:
            raise ValueError("DNS response omitted record ID; inspect DNS before retrying")
        return "DNS applied via " + profile["name"]

    def rollback_cname(self, change):
        profile = self.find_profile(change["profile_id"])
        current = self._records(profile, change["zone_id"], change["hostname"])
        if len(current) != 1 or current[0].get("id") != change["record_id"] or any(current[0].get(k) != change["body"][k] for k in ("type", "content", "proxied")):
            raise ValueError("DNS changed externally; restore it manually to avoid overwriting another change")
        path = "/zones/{}/dns_records/{}".format(change["zone_id"], change["record_id"])
        previous = change["previous"]
        if previous:
            body = {k: previous[k] for k in ("type", "name", "content", "proxied", "ttl") if k in previous}
            result = self._request("PATCH", path, self._auth_for_profile(profile), profile["name"], json=body)
        else:
            result = self._request("DELETE", path, self._auth_for_profile(profile), profile["name"])
        if not result["status"]:
            raise ValueError(result["msg"])

    @serialized
    def upsert_cname(self, hostname, target, zone_id="", proxied=True):
        try:
            change = self.prepare_cname(hostname, target, zone_id, proxied)
            return True, self.commit_cname(change)
        except ValueError as exc:
            return False, str(exc)

    @serialized
    def delete_cname(self, hostname, zone_id="", target="", profile_id="", record_id=""):
        # Deletion requires the exact ownership receipt saved when this plugin wrote DNS.
        if not target or not profile_id or not record_id or not zone_id:
            return False, "No DNS ownership receipt. Remove the CNAME manually in Cloudflare; other records were kept."
        try:
            profile = self.find_profile(profile_id)
            if not profile or not self._auth_for_profile(profile):
                raise ValueError("DNS profile unavailable; remove DNS manually")
            records = self._records(profile, zone_id, hostname)
            if not records:
                return True, "DNS already absent"
            if len(records) != 1 or records[0].get("type") != "CNAME" or records[0].get("content", "").lower().rstrip(".") != target.lower().rstrip(".") or records[0].get("id") != record_id:
                raise ValueError("DNS ownership conflict; records were kept. Review DNS manually.")
            result = self._request("DELETE", "/zones/{}/dns_records/{}".format(zone_id, record_id), self._auth_for_profile(profile), profile["name"])
            if not result["status"]:
                raise ValueError(result["msg"])
            return True, "DNS removed via " + profile["name"]
        except ValueError as exc:
            return False, str(exc)
