#!/usr/bin/python
# coding: utf-8
# Cloudflare Tunnel plugin for AAPanel.
# Dispatches /plugin?action=a&name=cloudflare_tunnel&s=<method> to per-domain modules.

import hashlib
import importlib.util
import json
import os
import sys
import threading
import types

PLUGIN_PATH = os.path.dirname(os.path.abspath(__file__))
_LOAD_LOCK = threading.RLock()
_HELPERS = ("storage", "dns_manager", "tunnel_manager", "ingress_manager")


def _modules():
    """Load this plugin's exact sources into a private, content-versioned package.

    aaPanel workers retain sys.modules across imports. Flat helper imports can bind
    to an older release or another plugin; timestamp-based .pyc can also survive an
    upgrade. Never reuse those modules or bytecode. In-flight requests keep their
    previous generation while new requests load the complete new generation.
    """
    sources = {}
    with open(os.path.join(PLUGIN_PATH, "manifest.json"), encoding="utf-8") as stream:
        manifest = json.load(stream)
    for name in _HELPERS:
        filename = name + ".py"
        with open(os.path.join(PLUGIN_PATH, filename), "rb") as stream:
            source = stream.read()
        if hashlib.sha256(source).hexdigest() != manifest["files"].get(filename):
            raise RuntimeError("Plugin update is incomplete. Import the complete plugin ZIP again.")
        sources[name] = source
    digest = hashlib.sha256(PLUGIN_PATH.encode() + b"".join(sources.values())).hexdigest()[:20]
    package_name = "_aapanel_cloudflare_tunnel_" + digest
    with _LOAD_LOCK:
        if package_name not in sys.modules:
            package = types.ModuleType(package_name)
            package.__path__ = [PLUGIN_PATH]
            package.__package__ = package_name
            sys.modules[package_name] = package
            try:
                for name, source in sources.items():
                    fullname = package_name + "." + name
                    path = os.path.join(PLUGIN_PATH, name + ".py")
                    spec = importlib.util.spec_from_file_location(fullname, path)
                    module = importlib.util.module_from_spec(spec)
                    sys.modules[fullname] = module
                    exec(compile(source, path, "exec"), module.__dict__)
            except Exception:
                for key in list(sys.modules):
                    if key == package_name or key.startswith(package_name + "."):
                        sys.modules.pop(key, None)
                raise
        return {name: sys.modules[package_name + "." + name] for name in _HELPERS}


def _call(module_name, class_name, method, get):
    try:
        manager = getattr(_modules()[module_name], class_name)()
        handler = getattr(manager, method, None)
        if handler is None:
            raise RuntimeError("Plugin files do not match. Import the complete plugin ZIP again.")
        return handler(get)
    except (OSError, RuntimeError, ImportError, KeyError, ValueError) as exc:
        return {"status": False, "msg": "Plugin could not complete this step: " + str(exc) + ". If this followed an upgrade, import the complete plugin ZIP again."}


class cloudflare_tunnel_main:
    # ---------- cloudflared binary + service ----------
    def get_status(self, get):
        return _call("tunnel_manager", "TunnelManager", "get_status", get)

    def install_cloudflared(self, get):
        return _call("tunnel_manager", "TunnelManager", "install_cloudflared", get)

    def uninstall_cloudflared(self, get):
        return _call("tunnel_manager", "TunnelManager", "uninstall_cloudflared", get)

    # ---------- auth (browser login + API token) ----------
    def cf_login_start(self, get):
        return _call("tunnel_manager", "TunnelManager", "cf_login_start", get)

    def cf_login_status(self, get):
        return _call("tunnel_manager", "TunnelManager", "cf_login_status", get)

    def set_api_token(self, get):
        return _call("dns_manager", "DnsManager", "set_api_token", get)

    def get_api_token_state(self, get):
        return _call("dns_manager", "DnsManager", "get_api_token_state", get)

    def clear_api_token(self, get):
        return _call("dns_manager", "DnsManager", "clear_api_token", get)

    # ---------- multi-account profiles (v1.2.0) ----------
    def list_profiles(self, get):
        return _call("dns_manager", "DnsManager", "list_profiles", get)

    def add_profile(self, get):
        return _call("dns_manager", "DnsManager", "add_profile", get)

    def delete_profile(self, get):
        return _call("dns_manager", "DnsManager", "delete_profile", get)

    def update_profile_token(self, get):
        return _call("dns_manager", "DnsManager", "update_profile_token", get)

    def update_profile_account(self, get):
        return _call("dns_manager", "DnsManager", "update_profile_account", get)

    def list_accounts(self, get):
        return _call("dns_manager", "DnsManager", "list_accounts", get)

    def select_account(self, get):
        return _call("dns_manager", "DnsManager", "select_account", get)

    # ---------- tunnels ----------
    def list_tunnels(self, get):
        return _call("tunnel_manager", "TunnelManager", "list_tunnels", get)

    def create_tunnel(self, get):
        return _call("tunnel_manager", "TunnelManager", "create_tunnel", get)

    def select_tunnel(self, get):
        return _call("tunnel_manager", "TunnelManager", "select_tunnel", get)

    def delete_tunnel(self, get):
        return _call("tunnel_manager", "TunnelManager", "delete_tunnel", get)

    # ---------- ingress (hostname → service) ----------
    def get_ingress(self, get):
        return _call("ingress_manager", "IngressManager", "get_ingress", get)

    def check_origin(self, get):
        return _call("ingress_manager", "IngressManager", "check_origin", get)

    def add_ingress(self, get):
        return _call("ingress_manager", "IngressManager", "add_ingress", get)

    def remove_ingress(self, get):
        return _call("ingress_manager", "IngressManager", "remove_ingress", get)

    def set_ingress_options(self, get):
        return _call("ingress_manager", "IngressManager", "set_ingress_options", get)

    def get_origin_request_fields(self, get):
        return {"status": True, "msg": "ok", "data": _modules()["ingress_manager"].ORIGIN_REQUEST_FIELDS}

    def apply_config(self, get):
        return _call("ingress_manager", "IngressManager", "apply_config", get)

    # ---------- DNS (zones + CNAME helpers) ----------
    def list_zones(self, get):
        return _call("dns_manager", "DnsManager", "list_zones", get)

    # ---------- service ----------
    def service_action(self, get):
        return _call("tunnel_manager", "TunnelManager", "service_action", get)

    def get_log(self, get):
        return _call("tunnel_manager", "TunnelManager", "get_log", get)
