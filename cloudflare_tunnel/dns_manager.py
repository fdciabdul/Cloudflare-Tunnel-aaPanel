#!/usr/bin/python
# coding: utf-8
# Cloudflare API helpers: API-token storage, zone lookup, CNAME upsert.

import json
import os

import requests
import public

CF_API = "https://api.cloudflare.com/client/v4"
# Where the cloudflare_manage plugin and aaPanel's DNS manager store creds.
GLOBAL_CF_DEFAULT = "/www/server/panel/plugin/cloudflare_manage/data/cf_default.json"
GLOBAL_DNS_MAGER = "/www/server/panel/config/dns_mager.conf"


class DnsManager:
    def __init__(self):
        self.plugin_dir = os.path.dirname(os.path.abspath(__file__))
        self.data_dir = os.path.join(self.plugin_dir, "data")
        if not os.path.exists(self.data_dir):
            os.makedirs(self.data_dir)
        self.token_file = os.path.join(self.data_dir, "api_token.json")

    # ---------- credential discovery ----------
    def _load_token(self):
        # Plugin-local token wins.
        if os.path.exists(self.token_file):
            try:
                tok = json.loads(public.readFile(self.token_file) or "{}").get("token", "")
                if tok:
                    return tok
            except Exception:
                pass
        return ""

    def _load_credentials(self):
        """Return (auth_headers, source_label) using, in order:
           1) plugin-local API token
           2) cloudflare_manage plugin's cf_default.json (API Key + Email, or API Token)
           3) aaPanel DNS manager (config/dns_mager.conf) first CloudFlareDns entry
        Returns (None, "") if no creds are available."""
        tok = self._load_token()
        if tok:
            return {"Authorization": "Bearer " + tok}, "plugin token"

        for path, label in (
            (GLOBAL_CF_DEFAULT, "cloudflare_manage default"),
            (GLOBAL_DNS_MAGER, "AAPanel DNS manager"),
        ):
            cfg = self._read_json(path)
            if not cfg:
                continue
            # dns_mager.conf wraps entries under CloudFlareDns
            candidates = cfg.get("CloudFlareDns", [cfg]) if isinstance(cfg, dict) else [cfg]
            for c in candidates:
                if not isinstance(c, dict):
                    continue
                token = c.get("API Token") or c.get("api_token")
                if token:
                    return {"Authorization": "Bearer " + token}, label + " (token)"
                email = c.get("E-Mail") or c.get("email")
                key = c.get("API Key") or c.get("api_key")
                if email and key:
                    return {"X-Auth-Email": email, "X-Auth-Key": key}, label + " (Global API Key)"
        return None, ""

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

    def set_api_token(self, get):
        token = (get.token or "").strip() if hasattr(get, "token") else ""
        if not token or len(token) < 20:
            return public.returnMsg(False, "Token looks invalid")
        # Verify with /user/tokens/verify before we store it.
        try:
            r = requests.get(
                CF_API + "/user/tokens/verify",
                headers={"Authorization": "Bearer " + token},
                timeout=15,
            ).json()
            if not r.get("success"):
                msg = (r.get("errors") or [{}])[0].get("message", "verify failed")
                return public.returnMsg(False, "Token rejected: " + msg)
        except Exception as e:
            return public.returnMsg(False, "Could not reach Cloudflare API: " + str(e))
        public.writeFile(self.token_file, json.dumps({"token": token}))
        os.chmod(self.token_file, 0o600)
        return public.returnMsg(True, "Token saved")

    def get_api_token_state(self, get):
        tok = self._load_token()
        creds, source = self._load_credentials()
        return {
            "status": True, "msg": "ok",
            "data": {
                "present": bool(tok),
                "tail": tok[-4:] if tok else "",
                "fallback_source": source,
                "any_creds": bool(creds),
            },
        }

    def clear_api_token(self, get):
        if os.path.exists(self.token_file):
            os.remove(self.token_file)
        return public.returnMsg(True, "Token cleared")

    # ---------- API call helper ----------
    def _request(self, method, path, **kwargs):
        auth, source = self._load_credentials()
        if not auth:
            return {"status": False, "msg": "No Cloudflare credentials available (set plugin token or configure cloudflare_manage)", "data": None}
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
            return {"status": False, "msg": "{} (via {})".format(msg, source), "data": r}
        return {"status": True, "msg": "ok", "data": r.get("result")}

    # ---------- zones ----------
    def list_zones(self, get):
        zones = []
        page = 1
        while True:
            r = self._request("GET", "/zones?per_page=50&page={}".format(page))
            if not r["status"]:
                return r
            chunk = r["data"] or []
            for z in chunk:
                zones.append({"id": z.get("id"), "name": z.get("name"), "status": z.get("status")})
            if len(chunk) < 50:
                break
            page += 1
            if page > 20:
                break
        return {"status": True, "msg": "ok", "data": zones}

    # ---------- CNAME upsert (used by ingress_manager) ----------
    def upsert_cname(self, hostname, target, zone_id="", proxied=True):
        """Create or update hostname CNAME -> target. Returns (ok, msg)."""
        if not zone_id:
            zid = self._zone_id_for_host(hostname)
            if not zid["status"]:
                return False, zid["msg"]
            zone_id = zid["data"]

        # Look for an existing record on this hostname.
        existing = self._request("GET", "/zones/{}/dns_records?name={}".format(zone_id, hostname))
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
            r = self._request("PUT", "/zones/{}/dns_records/{}".format(zone_id, rec["id"]), data=json.dumps(body))
        else:
            r = self._request("POST", "/zones/{}/dns_records".format(zone_id), data=json.dumps(body))
        if not r["status"]:
            return False, r["msg"]
        return True, "DNS record applied"

    def delete_cname(self, hostname, zone_id=""):
        if not zone_id:
            zid = self._zone_id_for_host(hostname)
            if not zid["status"]:
                return False, zid["msg"]
            zone_id = zid["data"]
        existing = self._request("GET", "/zones/{}/dns_records?name={}".format(zone_id, hostname))
        if not existing["status"]:
            return False, existing["msg"]
        for rec in (existing["data"] or []):
            self._request("DELETE", "/zones/{}/dns_records/{}".format(zone_id, rec["id"]))
        return True, "DNS record(s) removed"

    def _zone_id_for_host(self, hostname):
        # Match the longest zone whose name is a suffix of the hostname.
        zr = self.list_zones(None)
        if not zr["status"]:
            return zr
        best = None
        for z in zr["data"]:
            zn = z["name"]
            if hostname == zn or hostname.endswith("." + zn):
                if best is None or len(zn) > len(best["name"]):
                    best = z
        if not best:
            return {"status": False, "msg": "No Cloudflare zone matches {}".format(hostname), "data": None}
        return {"status": True, "msg": "ok", "data": best["id"]}
