#!/bin/bash
# AAPanel Import runs this after copying files into $PLUGIN_DIR. Do the cleanup +
# self-check that AAPanel's `\cp -a -r` doesn't do on its own, so partial upgrades
# (e.g. a v1.2.0 _main.py alongside a v1.1.x dns_manager.py) become visible immediately
# instead of surfacing later as `AttributeError: 'DnsManager' object has no attribute …`.
PATH=/www/server/panel/pyenv/bin:/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH
install_tmp='/tmp/bt_install.pl'
PLUGIN_DIR=/www/server/panel/plugin/cloudflare_tunnel

REQUIRED_FILES=(
    cloudflare_tunnel_main.py
    tunnel_manager.py
    dns_manager.py
    ingress_manager.py
    storage.py
    manifest.json
    index.html
    info.json
)

Install_cloudflare_tunnel()
{
    mkdir -p "${PLUGIN_DIR}/data"
    mkdir -p /etc/cloudflared

    # Purge stale bytecode from any prior version — Python's mtime check normally handles
    # this, but AAPanel's copy loses microsecond precision on some filesystems which can
    # tie the mtime and let stale .pyc win.
    rm -rf "${PLUGIN_DIR}/__pycache__"

    # Sanity-check: every module we ship must be present + non-empty. If AAPanel's Import
    # didn't fully overwrite (rare but observed on partial upgrades), surface it here
    # instead of dying at first UI action with an obscure AttributeError.
    missing=()
    for f in "${REQUIRED_FILES[@]}"; do
        if [ ! -s "${PLUGIN_DIR}/${f}" ]; then
            missing+=("$f")
        fi
    done
    if [ ${#missing[@]} -gt 0 ]; then
        echo "Installation incomplete — missing/empty files: ${missing[*]}" > $install_tmp
        echo "Fix: re-download the release zip and Import again, or run:" >> $install_tmp
        echo "  unzip -o /path/to/cloudflare_tunnel-1.4.0.zip -d ${PLUGIN_DIR}/ && bt restart" >> $install_tmp
        exit 1
    fi

    # Verify the exact archive, rather than accepting any older multi-profile file.
    panel_python=/www/server/panel/pyenv/bin/python3
    if [ ! -x "$panel_python" ]; then
        panel_python=$(command -v python3)
    fi
    if [ -z "$panel_python" ]; then
        echo 'Python 3 not found; plugin installation could not be verified.' > "$install_tmp"
        exit 1
    fi
    if ! "$panel_python" - "$PLUGIN_DIR" >> "$install_tmp" 2>&1 <<'PYVERIFY'
import ast
import hashlib
import json
import pathlib
import sys
root = pathlib.Path(sys.argv[1])
manifest = json.loads((root / "manifest.json").read_text())
for name, expected in manifest["files"].items():
    source = (root / name).read_bytes()
    if hashlib.sha256(source).hexdigest() != expected:
        raise SystemExit("Plugin files do not match: " + name + ". Import the complete ZIP again.")
    if name.endswith(".py"):
        compile(source, str(root / name), "exec")
source = ast.parse((root / "dns_manager.py").read_bytes())
manager = next(node for node in source.body if isinstance(node, ast.ClassDef) and node.name == "DnsManager")
methods = {node.name for node in manager.body if isinstance(node, ast.FunctionDef)}
required = {"update_profile_account", "list_accounts", "select_account", "update_profile_token", "list_profiles"}
if not required.issubset(methods):
    raise SystemExit("Incomplete plugin upgrade. Import the complete ZIP again.")
PYVERIFY
    then
        exit 1
    fi

    chmod 600 "${PLUGIN_DIR}"/*.py "${PLUGIN_DIR}"/*.json "${PLUGIN_DIR}"/index.html 2>/dev/null
    chmod 755 "${PLUGIN_DIR}/install.sh"
    echo 'Cloudflare Tunnel plugin installed. Open the plugin and follow the setup steps: browser login, API token, account, tunnel and hostname.' > $install_tmp
}

Uninstall_cloudflare_tunnel()
{
    # Stop the service if it's running; leave /etc/cloudflared so users don't lose creds
    # or tunnel credential files by accident on uninstall.
    if systemctl list-unit-files 2>/dev/null | grep -q '^cloudflared'; then
        systemctl stop cloudflared 2>/dev/null
        systemctl disable cloudflared 2>/dev/null
    fi
    rm -rf "${PLUGIN_DIR}"
    echo 'Cloudflare Tunnel plugin uninstalled. /etc/cloudflared kept intact.' > $install_tmp
}

action=$1
if [ "${1}" == 'install' ]; then
    Install_cloudflare_tunnel
else
    Uninstall_cloudflare_tunnel
fi
