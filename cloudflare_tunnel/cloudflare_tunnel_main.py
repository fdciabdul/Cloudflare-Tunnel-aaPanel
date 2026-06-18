#!/usr/bin/python
# coding: utf-8
# Cloudflare Tunnel plugin for AAPanel.
# Dispatches /plugin?action=a&name=cloudflare_tunnel&s=<method> to per-domain modules.

import os
import sys

os.chdir("/www/server/panel")
sys.path.append("class/")

PLUGIN_PATH = os.path.dirname(os.path.abspath(__file__))
if PLUGIN_PATH not in sys.path:
    sys.path.insert(0, PLUGIN_PATH)


class cloudflare_tunnel_main:
    # ---------- cloudflared binary + service ----------
    def get_status(self, get):
        from tunnel_manager import TunnelManager
        return TunnelManager().get_status(get)

    def install_cloudflared(self, get):
        from tunnel_manager import TunnelManager
        return TunnelManager().install_cloudflared(get)

    def uninstall_cloudflared(self, get):
        from tunnel_manager import TunnelManager
        return TunnelManager().uninstall_cloudflared(get)

    # ---------- auth (browser login + API token) ----------
    def cf_login_start(self, get):
        from tunnel_manager import TunnelManager
        return TunnelManager().cf_login_start(get)

    def cf_login_status(self, get):
        from tunnel_manager import TunnelManager
        return TunnelManager().cf_login_status(get)

    def set_api_token(self, get):
        from dns_manager import DnsManager
        return DnsManager().set_api_token(get)

    def get_api_token_state(self, get):
        from dns_manager import DnsManager
        return DnsManager().get_api_token_state(get)

    def clear_api_token(self, get):
        from dns_manager import DnsManager
        return DnsManager().clear_api_token(get)

    # ---------- tunnels ----------
    def list_tunnels(self, get):
        from tunnel_manager import TunnelManager
        return TunnelManager().list_tunnels(get)

    def create_tunnel(self, get):
        from tunnel_manager import TunnelManager
        return TunnelManager().create_tunnel(get)

    def select_tunnel(self, get):
        from tunnel_manager import TunnelManager
        return TunnelManager().select_tunnel(get)

    def delete_tunnel(self, get):
        from tunnel_manager import TunnelManager
        return TunnelManager().delete_tunnel(get)

    # ---------- ingress (hostname → service) ----------
    def get_ingress(self, get):
        from ingress_manager import IngressManager
        return IngressManager().get_ingress(get)

    def add_ingress(self, get):
        from ingress_manager import IngressManager
        return IngressManager().add_ingress(get)

    def remove_ingress(self, get):
        from ingress_manager import IngressManager
        return IngressManager().remove_ingress(get)

    def apply_config(self, get):
        from ingress_manager import IngressManager
        return IngressManager().apply_config(get)

    # ---------- DNS (zones + CNAME helpers) ----------
    def list_zones(self, get):
        from dns_manager import DnsManager
        return DnsManager().list_zones(get)

    # ---------- service ----------
    def service_action(self, get):
        from tunnel_manager import TunnelManager
        return TunnelManager().service_action(get)

    def get_log(self, get):
        from tunnel_manager import TunnelManager
        return TunnelManager().get_log(get)
