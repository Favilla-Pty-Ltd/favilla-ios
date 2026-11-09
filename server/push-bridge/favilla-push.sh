#!/usr/bin/env bash
# Install or update the Favilla push bridge on the relay box (9 Nov 2026).
#
# Usage, on the box, from the folder holding bridge.py and this script:
#   sudo bash favilla-push.sh /path/to/AuthKey_XXXXXXXXXX.p8 KEYID
# The .p8 is the APNs key from developer.apple.com (Keys), KEYID its Key ID.
# Re-running updates bridge.py and keeps the registrations.
#
# What it does:
#   - Python venv at /opt/favilla-push with websockets, aiohttp, httpx[http2], pyjwt
#   - config + APNs key in /etc/favilla-push (key readable by the service only)
#   - systemd service favilla-push (user favilla-push), listening on 127.0.0.1:8787
#   - nginx: https://relay.favillakey.io/push/ -> the service
set -euo pipefail

TEAM_ID="CWM3V36QPR"
TOPIC="io.favillakey.app"
SITE_NAME="relay.favillakey.io"
HERE="$(cd "$(dirname "$0")" && pwd)"

[ "$(id -u)" = 0 ] || { echo "run with sudo"; exit 1; }
[ -f "$HERE/bridge.py" ] || { echo "bridge.py must sit next to this script"; exit 1; }

if [ ! -f /etc/favilla-push/config.json ]; then
  P8="${1:-}"; KID="${2:-}"
  [ -f "$P8" ] && [[ "$KID" =~ ^[A-Z0-9]{10}$ ]] || { echo "first install: sudo bash favilla-push.sh /path/to/AuthKey_KEYID.p8 KEYID"; exit 1; }
fi

echo "== packages"
apt-get install -y -qq python3-venv >/dev/null
id favilla-push >/dev/null 2>&1 || useradd --system --home /var/lib/favilla-push --shell /usr/sbin/nologin favilla-push
mkdir -p /opt/favilla-push /etc/favilla-push /var/lib/favilla-push
[ -x /opt/favilla-push/venv/bin/python ] || python3 -m venv /opt/favilla-push/venv
/opt/favilla-push/venv/bin/pip install --quiet --upgrade websockets aiohttp "httpx[http2]" pyjwt cryptography
install -m 644 "$HERE/bridge.py" /opt/favilla-push/bridge.py

if [ ! -f /etc/favilla-push/config.json ]; then
  echo "== APNs key"
  install -m 600 -o favilla-push -g favilla-push "$P8" /etc/favilla-push/AuthKey.p8
  cat > /etc/favilla-push/config.json <<EOF
{"team_id": "$TEAM_ID", "key_id": "$KID", "key_path": "/etc/favilla-push/AuthKey.p8",
 "topic": "$TOPIC", "listen": "127.0.0.1:8787", "db": "/var/lib/favilla-push/devices.json"}
EOF
  chmod 644 /etc/favilla-push/config.json
fi
chown -R favilla-push:favilla-push /var/lib/favilla-push

echo "== service"
cat > /etc/systemd/system/favilla-push.service <<'EOF'
[Unit]
Description=Favilla push bridge (wakes the iPhone for Bluetooth bunker requests)
After=network-online.target
Wants=network-online.target

[Service]
User=favilla-push
ExecStart=/opt/favilla-push/venv/bin/python /opt/favilla-push/bridge.py /etc/favilla-push/config.json
Restart=always
RestartSec=3
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths=/var/lib/favilla-push
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable --now favilla-push >/dev/null
systemctl restart favilla-push

echo "== nginx"
cat > /etc/nginx/snippets/favilla-push.conf <<'EOF'
# Favilla push bridge (favilla-push.service)
location /push/ {
    proxy_pass http://127.0.0.1:8787;
    proxy_set_header X-Real-IP $remote_addr;
    client_max_body_size 16k;
}
EOF
SITE=$(grep -l "server_name[^;]*$SITE_NAME" /etc/nginx/sites-enabled/* 2>/dev/null | head -1 || true)
[ -n "$SITE" ] || { echo "no nginx site with server_name $SITE_NAME found; add 'include snippets/favilla-push.conf;' to its 443 server block by hand"; exit 1; }
SITE=$(readlink -f "$SITE")
if ! grep -q "snippets/favilla-push.conf" "$SITE"; then
  cp "$SITE" "$SITE.bak-push"
  # put the include right after server_name in every server block that listens on 443
  python3 - "$SITE" "$SITE_NAME" <<'EOF'
import re, sys
path, name = sys.argv[1], sys.argv[2]
s = open(path).read()
out, n = [], 0
blocks = re.split(r"(?=\bserver\s*\{)", s)
for b in blocks:
    if re.search(r"listen[^;]*443", b) and re.search(r"server_name[^;]*" + re.escape(name), b):
        b = re.sub(r"(server_name[^;]*;)", r"\1\n    include snippets/favilla-push.conf;", b, count=1)
        n += 1
    out.append(b)
open(path, "w").write("".join(out))
print(f"added the include to {n} server block(s)")
EOF
fi
nginx -t
systemctl reload nginx

echo "== check"
sleep 2
systemctl is-active favilla-push
curl -s https://$SITE_NAME/push/health; echo
echo "done. Logs: journalctl -u favilla-push -f"
