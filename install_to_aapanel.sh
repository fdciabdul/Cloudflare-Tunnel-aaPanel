#!/bin/bash
# Install (or symlink) the cloudflare_tunnel plugin into AAPanel.
#
#   ./install_to_aapanel.sh         # copy
#   ./install_to_aapanel.sh link    # symlink (dev mode, edits are live)
#   ./install_to_aapanel.sh remove  # remove from /www/server/panel/plugin

set -e
SRC="$(cd "$(dirname "$0")" && pwd)/cloudflare_tunnel"
DST="/www/server/panel/plugin/cloudflare_tunnel"
MODE="${1:-copy}"

if [ ! -d "/www/server/panel/plugin" ]; then
    echo "AAPanel plugin directory not found at /www/server/panel/plugin"
    exit 1
fi

case "$MODE" in
    link)
        rm -rf "$DST"
        ln -s "$SRC" "$DST"
        echo "Linked $DST -> $SRC"
        ;;
    remove)
        rm -rf "$DST"
        echo "Removed $DST"
        exit 0
        ;;
    copy|*)
        rm -rf "$DST"
        cp -r "$SRC" "$DST"
        echo "Copied to $DST"
        ;;
esac

mkdir -p "$DST/data" /etc/cloudflared
chmod +x "$DST/install.sh" 2>/dev/null || true
echo "Restart the panel (bt restart) and open Plugins → Cloudflare Tunnel."
