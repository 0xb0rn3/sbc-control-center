#!/usr/bin/env bash
set -Eeuo pipefail

APP_DIR="/opt/sbc-control-center"
ETC_DIR="/etc/sbc-control-center"
STATE_DIR="/var/lib/sbc-control-center"
GROUP="sbc-control-center"
USER="sbc-control-center"
read_hostapd_value() {
  local file="$1" key="$2"
  [[ -r "$file" ]] || return 0
  awk -F= -v key="$key" '$1 == key { sub(/^[[:space:]]+/, "", $2); sub(/[[:space:]]+$/, "", $2); print $2; exit }' "$file"
}

HOSTAPD_5G="/etc/hostapd/hostapd.conf"
HOSTAPD_2G="/etc/hostapd/hostapd-2g.conf"
AP_IFACE="${AP_IFACE:-$(read_hostapd_value "$HOSTAPD_5G" interface)}"
AP_IFACE="${AP_IFACE:-wlan1}"
AP_SSID="${AP_SSID:-$(read_hostapd_value "$HOSTAPD_5G" ssid)}"
AP_SSID="${AP_SSID:-SBC-5G}"
AP2_IFACE="${AP2_IFACE:-$(read_hostapd_value "$HOSTAPD_2G" interface)}"
AP2_IFACE="${AP2_IFACE:-wlan0}"
AP2_SSID="${AP2_SSID:-$(read_hostapd_value "$HOSTAPD_2G" ssid)}"
AP2_SSID="${AP2_SSID:-SBC-2G}"
AP_IP="${AP_IP:-10.50.0.1}"
AP_SUBNET="${AP_SUBNET:-10.50.0.0/24}"
AP2_IP="${AP2_IP:-10.60.0.1}"
AP2_SUBNET="${AP2_SUBNET:-10.60.0.0/24}"
detect_wireguard_interface() {
  [[ -d /etc/wireguard ]] || return 0
  find /etc/wireguard -maxdepth 1 -type f -name '*.conf' -printf '%f\n' 2>/dev/null | sort | head -n1 | sed 's/\.conf$//'
}
VPN_INTERFACE="${VPN_INTERFACE:-$(detect_wireguard_interface)}"
VPN_INTERFACE="${VPN_INTERFACE:-wg0}"
VPN_UNIT="${VPN_UNIT:-wg-quick@${VPN_INTERFACE}}"
SUDO_AUTH_USER="${SUDO_AUTH_USER:-${SUDO_USER:-}}"
PORTAL_HOSTNAME="${PORTAL_HOSTNAME:-sbc-control-center.local}"

for iface in "$AP_IFACE" "$AP2_IFACE" "$VPN_INTERFACE"; do
  [[ "$iface" =~ ^[A-Za-z0-9_.:-]{1,32}$ ]] || { echo "Invalid interface name: $iface" >&2; exit 1; }
done
[[ "$VPN_UNIT" =~ ^wg-quick@[A-Za-z0-9_.-]{1,32}$ ]] || { echo "VPN_UNIT must be a wg-quick@ interface unit." >&2; exit 1; }
[[ "$PORTAL_HOSTNAME" =~ ^([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$ ]] || { echo "PORTAL_HOSTNAME must be a DNS hostname containing at least one dot." >&2; exit 1; }
for ssid in "$AP_SSID" "$AP2_SSID"; do
  [[ -n "$ssid" && ${#ssid} -le 32 && "$ssid" != *$'\n'* ]] || { echo "AP SSIDs must be 1–32 characters without line breaks." >&2; exit 1; }
done

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run this installer as root: bash install.sh" >&2
  exit 1
fi

if [[ -r /etc/os-release ]]; then
  . /etc/os-release
  if [[ "${ID:-}" != "debian" ]]; then
    echo "Warning: this installer is designed for Debian 13/Trixie. Detected: ${PRETTY_NAME:-unknown}" >&2
    read -r -p "Continue anyway? [y/N] " answer
    [[ "${answer,,}" == "y" ]] || exit 1
  fi
fi

SRC="${SBC_CONTROL_CENTER_SOURCE:-$(cd "$(dirname "$0")" && pwd)}"
missing=()
for f in agent.py web.py sbc_site.py index.html standby.html assets/ui-background.png assets/ui/slideshow.js assets/vendor/xterm.js; do
  [[ -f "$SRC/$f" ]] || missing+=("$f")
done
if (( ${#missing[@]} )); then
  echo "SBC Control Center source files were not found in: $SRC" >&2
  exit 1
fi

python3 - "$SRC/assets/ui-background.png" <<'PY'
import pathlib, sys
p = pathlib.Path(sys.argv[1])
data = p.read_bytes()
if len(data) > 4_000_000 or data[:8] != b'\x89PNG\r\n\x1a\n':
    raise SystemExit('Portal background must be a valid PNG no larger than 4 MB.')
print(f'Portal background asset: {len(data):,} bytes')
PY

printf '\n[1/7] Installing required packages (packages/debian-required.txt, AdGuard Home, DB-IP)...\n'
bash "$SRC/tools/install-dependencies.sh" ${SBC_WITH_OPTIONAL:+--all}

printf '\n[2/7] Creating restricted portal account...\n'
getent group "$GROUP" >/dev/null || groupadd --system "$GROUP"
if ! id "$USER" >/dev/null 2>&1; then
  useradd --system --home-dir /nonexistent --shell /usr/sbin/nologin --gid "$GROUP" "$USER"
fi

install -d -o root -g "$GROUP" -m 0750 "$APP_DIR" "$ETC_DIR" "$STATE_DIR"
install -d -o "$USER" -g "$GROUP" -m 0700 /var/lib/sbc-control-center-web
# every application file: Python modules, the page, the TV page, assets (wallpapers stay yours)
(cd "$SRC" && find . -type f \( -name '*.py' -o -name '*.html' -o -path './assets/*' -o -name VERSION \) \
   ! -path './tests/*' ! -path './tools/*' ! -path './.git/*' ! -path './assets/wallpapers/*' -print0) |
while IFS= read -r -d '' f; do
  f=${f#./}; mode=0644
  case "$f" in agent.py|web.py|set_password.py|configure_mfa.py|sbc_admin.py) mode=0755;; esac
  install -D -o root -g root -m "$mode" "$SRC/$f" "$APP_DIR/$f"
done
install -d -o root -g root -m 0755 "$APP_DIR/assets/wallpapers"

python3 - "$ETC_DIR/config.json" "$AP_IFACE" "$AP_SSID" "$AP_IP" "$AP_SUBNET" "$VPN_INTERFACE" "$VPN_UNIT" "$AP2_IFACE" "$AP2_SSID" "$AP2_IP" "$AP2_SUBNET" <<'PY'
import json, os, sys, tempfile
path, ap_iface, ap_ssid, ap_ip, ap_subnet, vpn_iface, vpn_unit, ap2_iface, ap2_ssid, ap2_ip, ap2_subnet = sys.argv[1:]
payload = {
    "ap_interface": ap_iface, "ap_ssid": ap_ssid, "ap_ip": ap_ip, "ap_subnet": ap_subnet,
    "vpn_interface": vpn_iface, "vpn_unit": vpn_unit,
    "dhcp_lease_file": "/var/lib/misc/dnsmasq.leases",
    "ap2_interface": ap2_iface, "ap2_ssid": ap2_ssid, "ap2_ip": ap2_ip, "ap2_subnet": ap2_subnet,
}
fd, temp_path = tempfile.mkstemp(prefix='.config-', dir=os.path.dirname(path))
try:
    with os.fdopen(fd, 'w', encoding='utf-8') as stream:
        json.dump(payload, stream, indent=2)
        stream.write('\n')
        stream.flush()
        os.fsync(stream.fileno())
    os.chmod(temp_path, 0o640)
    os.replace(temp_path, path)
finally:
    try: os.unlink(temp_path)
    except FileNotFoundError: pass
PY
chown root:"$GROUP" "$ETC_DIR/config.json"
chmod 0640 "$ETC_DIR/config.json"

if [[ -z "$SUDO_AUTH_USER" ]]; then
  if [[ -r /dev/tty ]]; then
    read -r -p "Linux sudo-capable username for fresh privileged-action verification: " SUDO_AUTH_USER </dev/tty
  else
    echo "Set SUDO_AUTH_USER to a Linux account with sudo access before installation." >&2
    exit 1
  fi
fi
getent passwd "$SUDO_AUTH_USER" >/dev/null || { echo "Linux account '$SUDO_AUTH_USER' does not exist." >&2; exit 1; }
sudo -l -U "$SUDO_AUTH_USER" >/dev/null 2>&1 || { echo "Linux account '$SUDO_AUTH_USER' does not have sudo permission. Configure sudoers first." >&2; exit 1; }
python3 - "$ETC_DIR/privilege.json" "$SUDO_AUTH_USER" <<'PYPRIV'
import grp, json, os, sys, tempfile
path, username = sys.argv[1:]
fd, temp_path = tempfile.mkstemp(prefix='.privilege-', dir=os.path.dirname(path))
try:
    with os.fdopen(fd, 'w', encoding='utf-8') as stream:
        json.dump({'sudo_user': username}, stream)
        stream.write('\n')
        stream.flush()
        os.fsync(stream.fileno())
    os.chmod(temp_path, 0o640)
    os.chown(temp_path, 0, grp.getgrnam('sbc-control-center').gr_gid)
    os.replace(temp_path, path)
finally:
    try: os.unlink(temp_path)
    except FileNotFoundError: pass
PYPRIV

if [[ ! -s "$ETC_DIR/session.key" ]]; then
  openssl rand -hex 48 > "$ETC_DIR/session.key"
fi
chown root:"$GROUP" "$ETC_DIR/session.key"
chmod 0640 "$ETC_DIR/session.key"

printf '\n[3/7] Creating local HTTPS certificate...\n'
if [[ ! -s "$ETC_DIR/tls.crt" || ! -s "$ETC_DIR/tls.key" ]]; then
  openssl req -x509 -newkey rsa:3072 -sha256 -nodes -days 825 \
    -keyout "$ETC_DIR/tls.key" -out "$ETC_DIR/tls.crt" \
    -subj "/CN=${PORTAL_HOSTNAME}/O=SBC Control Center" \
    -addext "subjectAltName=DNS:${PORTAL_HOSTNAME},IP:${AP_IP}" \
    >/dev/null 2>&1
fi
chown root:"$GROUP" "$ETC_DIR/tls.crt" "$ETC_DIR/tls.key"
chmod 0640 "$ETC_DIR/tls.crt" "$ETC_DIR/tls.key"

printf '\n[4/7] Adding the portal exception before the AP input drop...\n'
if [[ -f /etc/apguard.nft ]] && command -v nft >/dev/null 2>&1; then
  python3 - <<'PY'
from pathlib import Path
p = Path('/etc/apguard.nft')
s = p.read_text()
rules = [
    ('iifname $AP5 tcp dport 8443 accept', 'iifname $AP5 counter drop'),
    ('iifname $AP2 tcp dport 8443 accept', 'iifname $AP2 counter drop'),
    ('iifname $AP tcp dport 8443 accept', 'iifname $AP counter drop'),
]
changed = False
for rule, anchor in rules:
    if rule in s:
        continue
    if anchor in s:
        if not changed:
            backup = p.with_suffix('.nft.pre-control-center.bak')
            if not backup.exists():
                backup.write_text(s)
        s = s.replace(anchor, rule + '\n        ' + anchor, 1)
        changed = True
if changed:
    p.write_text(s)
    print('Inserted TCP/8443 allow rule(s) before the AP input drop(s).')
else:
    if any(rule in s for rule, _ in rules):
        print('Portal firewall rule(s) already exist.')
    else:
        raise SystemExit('Could not find an AP input drop anchor in /etc/apguard.nft; no firewall changes made.')
PY
  nft -c -f /etc/apguard.nft
  nft -f /etc/apguard.nft
else
  echo "WARNING: /etc/apguard.nft not found. You may need to allow TCP 8443 from the AP interface manually." >&2
fi

printf '\n[5/7] Installing systemd units...\n'
cat > /etc/systemd/system/sbc-control-center-agent.service <<'EOF'
[Unit]
Description=SBC Control Center privileged allow-listed agent
After=local-fs.target dbus.service

[Service]
Type=simple
User=root
Group=sbc-control-center
RuntimeDirectory=sbc-control-center
RuntimeDirectoryMode=0750
ExecStart=/usr/bin/python3 /opt/sbc-control-center/agent.py
Restart=on-failure
RestartSec=2
PrivateTmp=yes
ProtectHome=yes
NoNewPrivileges=yes

ProtectSystem=strict
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
LockPersonality=yes
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK AF_PACKET
AmbientCapabilities=CAP_NET_RAW
SystemCallArchitectures=native
ReadWritePaths=/etc/sbc-control-center /var/lib/sbc-control-center /run/sbc-control-center -/etc/hostapd -/etc/dnsmasq.d -/etc/apguard.nft -/etc/systemd/system/ap-iface.service -/etc/systemd/system/ap2-iface.service -/etc/systemd/system/apguard.service -/etc/systemd/system/hostapd-2g.service -/etc/systemd/system/multi-user.target.wants
[Install]
WantedBy=multi-user.target
EOF

cat > /etc/systemd/system/sbc-control-center-web.service <<EOF
[Unit]
Description=SBC Control Center HTTPS web portal
After=network-online.target sbc-control-center-agent.service
Requires=sbc-control-center-agent.service
Wants=network-online.target

[Service]
Type=simple
User=sbc-control-center
Group=sbc-control-center
Environment=PORTAL_BIND=0.0.0.0
Environment=PORTAL_PORT=8443
Environment=PORTAL_WEBAUTHN_RP_ID=${PORTAL_HOSTNAME}
ExecStart=/usr/bin/python3 /opt/sbc-control-center/web.py
Restart=on-failure
RestartSec=3
UMask=0077
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
StateDirectory=sbc-control-center-web
StateDirectoryMode=0700
RestrictSUIDSGID=yes
LockPersonality=yes
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6

[Install]
WantedBy=multi-user.target
EOF

printf '\n[6/7] Setting the administrator password...\n'
python3 "$APP_DIR/set_password.py"

printf '\n[7/7] Starting Control Center...\n'
systemctl daemon-reload
systemctl enable --now sbc-control-center-agent.service sbc-control-center-web.service
# monthly IEEE vendor registry refresh (the unit is written by the program it runs)
python3 "$APP_DIR/sbc_admin.py" oui install-units

# HomeTube (github.com/0xb0rn3/hometube): YouTube for the TV, served by this board at /tv. Optional.
#   INSTALL_HOMETUBE=yes|no answers the question in advance.
INSTALL_HOMETUBE="${INSTALL_HOMETUBE:-}"
if [[ -z "$INSTALL_HOMETUBE" && -t 0 ]]; then
  read -r -p "Install HomeTube (YouTube for your TV, served by this board at /tv)? [y/N] " answer
  [[ "${answer,,}" == "y" ]] && INSTALL_HOMETUBE=yes || INSTALL_HOMETUBE=no
fi
if [[ "${INSTALL_HOMETUBE,,}" == "yes" ]]; then
  printf '\n[+] HomeTube...\n'
  HT_SRC=$(mktemp -d)
  curl -fsSL --retry 3 https://github.com/0xb0rn3/hometube/archive/refs/heads/main.tar.gz | tar -xz -C "$HT_SRC" --strip-components=1
  HT_ARGS=(--bind 127.0.0.1 --port 8891)
  # HomeTube's own traffic through the VPN tunnel when its table (200) is in place; it then checks
  # before every request to YouTube that it leaves by the tunnel, and refuses otherwise
  if ip -4 route show table 200 2>/dev/null | grep -q "dev $VPN_INTERFACE"; then
    HT_ARGS+=(--route-table 200 --route-dev "$VPN_INTERFACE" --after "$VPN_UNIT.service")
  fi
  bash "$HT_SRC/install.sh" "${HT_ARGS[@]}"
  rm -rf "$HT_SRC"
fi

AP_ADDR="$AP_IP"
ETH_ADDR="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src") {print $(i+1); exit}}' || true)"

cat <<EOF

============================================================
 SBC Control Center installed
============================================================
 AP / Access point:  https://${AP_ADDR}:8443
 Passkey portal:     https://${PORTAL_HOSTNAME}:8443
 Uplink LAN access:  https://${ETH_ADDR:-<SBC-LAN-IP>}:8443

 First visit: your browser will warn about the local
 self-signed HTTPS certificate. Verify you are on your
 own network. To use passkeys, install/trust that certificate
 and open the portal through ${PORTAL_HOSTNAME} (not an IP).

 Check services:
   systemctl status sbc-control-center-agent sbc-control-center-web

 Portal logs:
   journalctl -u sbc-control-center-web -n 80 --no-pager

 Keep TCP/8443 off public WAN port-forwarding.
============================================================
EOF
