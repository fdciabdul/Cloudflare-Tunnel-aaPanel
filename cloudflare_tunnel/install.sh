#!/bin/bash
PATH=/www/server/panel/pyenv/bin:/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH
install_tmp='/tmp/bt_install.pl'
PLUGIN_DIR=/www/server/panel/plugin/cloudflare_tunnel

Install_cloudflare_tunnel()
{
    mkdir -p ${PLUGIN_DIR}/data
    mkdir -p /etc/cloudflared
    echo 'Cloudflare Tunnel plugin installed. Install cloudflared from the plugin UI.' > $install_tmp
}

Uninstall_cloudflare_tunnel()
{
    # Stop service if running; leave /etc/cloudflared so users don't lose creds by accident.
    if systemctl list-unit-files | grep -q '^cloudflared'; then
        systemctl stop cloudflared 2>/dev/null
        systemctl disable cloudflared 2>/dev/null
    fi
    rm -rf ${PLUGIN_DIR}
    echo 'Cloudflare Tunnel plugin uninstalled. /etc/cloudflared kept intact.' > $install_tmp
}

action=$1
if [ "${1}" == 'install' ];then
    Install_cloudflare_tunnel
else
    Uninstall_cloudflare_tunnel
fi
