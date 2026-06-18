# Cloudflare Tunnel for AAPanel

Expose any AAPanel site through a Cloudflare Tunnel (cloudflared) — without opening a port, owning a public IP, or touching nginx vhosts. All ingress mapping, DNS, and the systemd service are managed from the panel UI.

<p align="center">
  <img src="cloudflare_tunnel/icon.png" alt="logo" width="128"/>
</p>

## Features

- One-click install/update of the `cloudflared` binary
- Browser login (`cloudflared tunnel login`) **and** API-token auth (verified before save)
- Tunnel CRUD via the cloudflared CLI (create / list / select / delete)
- Hostname → local service ingress rules (`http://127.0.0.1:8080`, `tcp://…`, `http_status:404`, `hello_world`)
- Auto-creates / upserts the public CNAME on Cloudflare (`<sub>.zone → <tunnel-id>.cfargotunnel.com`, proxied)
- Reuses the **existing Cloudflare credentials** stored by AAPanel's `cloudflare_manage` plugin / DNS manager — no need to re-enter your token
- Atomic add: if DNS or config-apply fails, the ingress row is rolled back
- Materializes a real `credentials-file` from a tunnel token, so `cloudflared service install` works on tunnels created before the plugin existed
- systemd lifecycle controls: install / start / stop / restart / uninstall
- Live `journalctl` view in the Logs tab

## Install

### From the plugin archive (recommended)

1. Download the latest [`dist/cloudflare_tunnel-1.0.6.zip`](dist/cloudflare_tunnel-1.0.6.zip).
2. AAPanel → **App Store** → top-right **Import** (upload icon) → pick the zip.
3. Open the plugin → **Status** tab → *Install / Update cloudflared*.

### From source (dev / symlink)

```bash
git clone https://github.com/fdciabdul/Cloudflare-Tunnel-aaPanel.git
cd Cloudflare-Tunnel-aaPanel
./install_to_aapanel.sh link    # symlink — edits go live without re-packaging
# or
./install_to_aapanel.sh         # copy
```

The script symlinks/copies `cloudflare_tunnel/` into `/www/server/panel/plugin/cloudflare_tunnel/`. Bounce the panel (`bt restart`) after first install or if you change Python files.

## Quick start

1. **Status** → *Install / Update cloudflared*
2. **Auth** → either *Get login URL* (browser) **or** paste an API token with `Zone:DNS:Edit` (+ `Account:Cloudflare Tunnel:Edit` if you want create/delete via the API). If `cloudflare_manage` is already configured, the plugin uses those creds automatically.
3. **Tunnels** → create a new tunnel (e.g. `aapanel`) → *Use*
4. **Status** → *Install service*
5. **Hostnames** → add `app.example.com → http://127.0.0.1:8080` — done.

## Architecture

```
cloudflare_tunnel/
├── info.json                  panel metadata
├── install.sh                 AAPanel install/uninstall hook
├── icon.png                   plugin tile icon
├── cloudflare_tunnel_main.py  dispatcher for /plugin?action=a&name=cloudflare_tunnel&s=…
├── tunnel_manager.py          cloudflared binary, login, tunnel CRUD, systemd
├── dns_manager.py             credential discovery + Cloudflare API (zones, CNAME upsert)
├── ingress_manager.py         hostname↔service rules, config.yml writer
├── index.html                 5-tab UI (Status / Auth / Tunnels / Hostnames / Logs)
└── data/                      runtime: state.json, ingress.json, api_token.json (gitignored)
```

### Credential precedence

The plugin looks for Cloudflare API credentials in this order:

1. Plugin-local API token (Auth tab)
2. `cloudflare_manage` plugin's `cf_default.json` (Global API Key + Email **or** API Token)
3. AAPanel DNS manager: first `CloudFlareDns` entry in `/www/server/panel/config/dns_mager.conf`

### Remote-managed tunnels

If you select a tunnel that was configured in the Cloudflare Zero Trust dashboard, cloudflared will ignore the local `config.yml` and pull ingress from the dashboard. Either switch it to locally-managed in the dashboard, or create a fresh tunnel through this plugin.

## Build the archive yourself

```bash
cd cloudflare_tunnel
zip -r ../dist/cloudflare_tunnel-$(jq -r .versions info.json).zip . \
    -x "data/*" "__pycache__/*" "*.pyc"
```

## License

MIT
