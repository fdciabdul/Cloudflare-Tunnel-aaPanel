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
import json
import os
import shutil
import time

import requests
import public

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
        if len(no_cert) == 1:
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
        if not os.path.exists(self.profiles_file):
            return []
        try:
            data = json.loads(public.readFile(self.profiles_file) or "[]")
            return data if isinstance(data, list) else []
        except Exception:
            return []

    def _write_profiles(self, profiles):
        public.writeFile(self.profiles_file, json.dumps(profiles, indent=2))
        os.chmod(self.profiles_file, 0o600)

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
        for p in self._all_profiles():
            if p["id"] == profile_id:
                return p
        return None

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
        return {"Authorization": "Bearer " + profile["token"]}

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
            out.append({
                "id": p["id"],
                "name": p.get("name") or p["id"],
                "virtual": False,
                "tail": tok[-4:] if tok else "",
                "has_token": bool(tok),
                "logged_in": bool(cert_path and os.path.exists(cert_path)),
                "cert_path": cert_path,
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

    def add_profile(self, get):
        # `profile_name` (not `name`) avoids the aaPanel plugin-id URL-param collision.
        name = ((get.name_ if hasattr(get, "name_") else "") or (get.profile_name if hasattr(get, "profile_name") else "")).strip()
        token = (get.token or "").strip() if hasattr(get, "token") else ""
        if not name:
            return public.returnMsg(False, "Profile name required")
        # v1.3.0: token is optional at add-time — user can create the profile shell first,
        # do browser login (which sets cert_path), then paste the token later. Or vice versa.
        if token:
            if len(token) < 20:
                return public.returnMsg(False, "Token looks invalid")
            try:
                r = requests.get(
                    CF_API + "/user/tokens/verify",
                    headers={"Authorization": "Bearer " + token}, timeout=15,
                ).json()
                if not r.get("success"):
                    msg = (r.get("errors") or [{}])[0].get("message", "verify failed")
                    return public.returnMsg(False, "Token rejected: " + msg)
            except Exception as e:
                return public.returnMsg(False, "Could not reach Cloudflare API: " + str(e))

        profiles = self._read_profiles()
        if any(p.get("name") == name for p in profiles):
            return public.returnMsg(False, "A profile with that name already exists")
        if token and any(p.get("token") == token for p in profiles):
            return public.returnMsg(False, "This token is already registered under another profile")

        pid = self._new_id(name)
        profiles.append({"id": pid, "name": name, "token": token, "cert_path": ""})
        self._write_profiles(profiles)
        DnsManager._zones_cache.clear()
        return {"status": True, "msg": "Profile added", "data": {"id": pid, "name": name}}

    def update_profile_token(self, get):
        """Attach or replace an API token on an existing profile without touching cert.
        Useful for the 'legacy (add token)' migrated profile, or to rotate keys."""
        pid = (get.profile_id or "").strip() if hasattr(get, "profile_id") else ""
        token = (get.token or "").strip() if hasattr(get, "token") else ""
        if not pid or pid.startswith("__"):
            return public.returnMsg(False, "profile_id required (virtual profiles can't be edited)")
        if not token or len(token) < 20:
            return public.returnMsg(False, "Token looks invalid")
        try:
            r = requests.get(
                CF_API + "/user/tokens/verify",
                headers={"Authorization": "Bearer " + token}, timeout=15,
            ).json()
            if not r.get("success"):
                msg = (r.get("errors") or [{}])[0].get("message", "verify failed")
                return public.returnMsg(False, "Token rejected: " + msg)
        except Exception as e:
            return public.returnMsg(False, "Could not reach Cloudflare API: " + str(e))
        profiles = self._read_profiles()
        for p in profiles:
            if p.get("id") == pid:
                p["token"] = token
                self._write_profiles(profiles)
                DnsManager._zones_cache.clear()
                return public.returnMsg(True, "Token updated")
        return public.returnMsg(False, "Profile not found")

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
        # Clean the associated cert.pem too — orphan files pile up otherwise.
        if removed and removed.get("cert_path"):
            try: os.remove(removed["cert_path"])
            except Exception: pass
        self._write_profiles(new)
        DnsManager._zones_cache.clear()
        return public.returnMsg(True, "Profile removed")

    # ---------- back-compat convenience API (older UI still calls these) ----------
    def set_api_token(self, get):
        """Legacy single-token setter — creates/updates a profile called 'default'."""
        token = (get.token or "").strip() if hasattr(get, "token") else ""
        if not token or len(token) < 20:
            return public.returnMsg(False, "Token looks invalid")
        try:
            r = requests.get(
                CF_API + "/user/tokens/verify",
                headers={"Authorization": "Bearer " + token}, timeout=15,
            ).json()
            if not r.get("success"):
                msg = (r.get("errors") or [{}])[0].get("message", "verify failed")
                return public.returnMsg(False, "Token rejected: " + msg)
        except Exception as e:
            return public.returnMsg(False, "Could not reach Cloudflare API: " + str(e))

        profiles = self._read_profiles()
        default = next((p for p in profiles if p.get("name") == "default"), None)
        if default:
            default["token"] = token
        else:
            profiles.append({"id": self._new_id("default"), "name": "default", "token": token})
        self._write_profiles(profiles)
        DnsManager._zones_cache.clear()
        return public.returnMsg(True, "Token saved to 'default' profile")

    def clear_api_token(self, get):
        """Legacy: removes the 'default' profile if one exists."""
        profiles = self._read_profiles()
        new = [p for p in profiles if p.get("name") != "default"]
        self._write_profiles(new)
        DnsManager._zones_cache.clear()
        return public.returnMsg(True, "Default profile removed")

    def get_api_token_state(self, get):
        profiles = self._all_profiles()
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
            return {"status": False, "msg": "No Cloudflare credentials available", "data": None}
        headers = kwargs.pop("headers", {}) or {}
        headers.update(auth)
        headers.setdefault("Content-Type", "application/json")
        kwargs.setdefault("timeout", 30)
        try:
            r = requests.request(method, CF_API + path, headers=headers, **kwargs).json()
        except Exception as e:
            return {"status": False, "msg": str(e), "data": None}
        if not r.get("success"):
            msg = (r.get("errors") or [{}])[0].get("message", "API error")
            if source_label:
                msg = "{} (via {})".format(msg, source_label)
            return {"status": False, "msg": msg, "data": r}
        return {"status": True, "msg": "ok", "data": r.get("result")}

    # ---------- zones ----------
    def _list_zones_for_profile(self, profile):
        """Cached per-profile zone list. Returns [] on API error so callers can still
        try other profiles instead of failing hard."""
        pid = profile["id"]
        entry = DnsManager._zones_cache.get(pid)
        if entry and (time.time() - entry["at"]) < _ZONES_CACHE_TTL:
            return entry["zones"]
        auth = self._auth_for_profile(profile)
        zones = []
        page = 1
        while page <= 20:
            r = self._request("GET", "/zones?per_page=50&page={}".format(page), auth, profile["name"])
            if not r["status"]:
                # Cache empty to avoid retry storms; TTL will refresh eventually.
                break
            chunk = r["data"] or []
            for z in chunk:
                zones.append({"id": z.get("id"), "name": z.get("name"), "status": z.get("status")})
            if len(chunk) < 50:
                break
            page += 1
        DnsManager._zones_cache[pid] = {"at": time.time(), "zones": zones}
        return zones

    def list_zones(self, get):
        """Aggregate zones from all profiles. Each entry is tagged with profile info so
        the UI can label 'example.com (Account: work)'. Dedupe by zone id — if the same
        zone appears under multiple credentials, prefer the first profile listed (which
        puts user-added profiles above virtual fallbacks)."""
        seen = set()
        out = []
        errors = []
        for p in self._all_profiles():
            try:
                zones = self._list_zones_for_profile(p)
            except Exception as e:
                errors.append("{}: {}".format(p["name"], e))
                continue
            for z in zones:
                if z["id"] in seen:
                    continue
                seen.add(z["id"])
                z2 = dict(z)
                z2["profile_id"] = p["id"]
                z2["profile_name"] = p["name"]
                out.append(z2)
        if not out and errors:
            return {"status": False, "msg": "; ".join(errors), "data": []}
        return {"status": True, "msg": "ok", "data": out}

    def _resolve_zone_for_host(self, hostname, zone_id_hint=""):
        """Given a hostname, return (profile, zone_id) that owns it.
        If zone_id_hint is supplied (from the UI dropdown), match the zone by id
        first — that's authoritative because the user picked it."""
        for p in self._all_profiles():
            for z in self._list_zones_for_profile(p):
                if zone_id_hint and z["id"] == zone_id_hint:
                    return p, z["id"], None
        # No hint or no match: longest-suffix match across all profiles.
        best = None
        for p in self._all_profiles():
            for z in self._list_zones_for_profile(p):
                zn = z["name"]
                if hostname == zn or hostname.endswith("." + zn):
                    if best is None or len(zn) > len(best[1]["name"]):
                        best = (p, z)
        if not best:
            return None, None, "No Cloudflare zone matches {}".format(hostname)
        return best[0], best[1]["id"], None

    # ---------- CNAME upsert (used by ingress_manager) ----------
    def upsert_cname(self, hostname, target, zone_id="", proxied=True):
        """Create or update hostname CNAME -> target. Returns (ok, msg)."""
        profile, resolved_zone, err = self._resolve_zone_for_host(hostname, zone_id_hint=zone_id)
        if err:
            return False, err
        zone_id = resolved_zone
        auth = self._auth_for_profile(profile)

        existing = self._request("GET", "/zones/{}/dns_records?name={}".format(zone_id, hostname), auth, profile["name"])
        if not existing["status"]:
            return False, existing["msg"]

        body = {
            "type": "CNAME",
            "name": hostname,
            "content": target,
            "proxied": bool(proxied),
            "ttl": 1,
        }
        records = existing["data"] or []
        if records:
            rec = records[0]
            r = self._request("PUT", "/zones/{}/dns_records/{}".format(zone_id, rec["id"]), auth, profile["name"], data=json.dumps(body))
        else:
            r = self._request("POST", "/zones/{}/dns_records".format(zone_id), auth, profile["name"], data=json.dumps(body))
        if not r["status"]:
            return False, r["msg"]
        return True, "DNS applied via {}".format(profile["name"])

    def delete_cname(self, hostname, zone_id=""):
        profile, resolved_zone, err = self._resolve_zone_for_host(hostname, zone_id_hint=zone_id)
        if err:
            return False, err
        zone_id = resolved_zone
        auth = self._auth_for_profile(profile)

        existing = self._request("GET", "/zones/{}/dns_records?name={}".format(zone_id, hostname), auth, profile["name"])
        if not existing["status"]:
            return False, existing["msg"]
        for rec in (existing["data"] or []):
            self._request("DELETE", "/zones/{}/dns_records/{}".format(zone_id, rec["id"]), auth, profile["name"])
        return True, "DNS removed via {}".format(profile["name"])
