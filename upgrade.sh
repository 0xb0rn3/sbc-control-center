#!/usr/bin/env bash
set -Eeuo pipefail

APP_DIR="/opt/sbc-control-center"
SRC="$(cd "$(dirname "$0")" && pwd)"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
BACKUP_DIR="/var/backups/sbc-control-center/pre-v0.0.1-1-${STAMP}"
UPGRADE_ACTIVE=0
ASSET_BACKUP=0
UNIT_BACKUP=0
PORTAL_HOSTNAME="${PORTAL_HOSTNAME:-sbc-control-center.local}"

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run as root: bash upgrade.sh" >&2
  exit 1
fi
for file in agent.py web.py telemetry.py pam_auth.py index.html set_password.py configure_mfa.py VERSION; do
  [[ -f "$SRC/$file" ]] || { echo "Missing upgrade file: $SRC/$file" >&2; exit 1; }
done
[[ -f "$SRC/assets/ui-background.png" ]] || { echo "Missing supplied UI background asset." >&2; exit 1; }

printf '\n[1/7] Preflighting v0.0.1-1 source, asset and tests...\n'
python3 - "$SRC" <<'PY'
import pathlib, sys
root = pathlib.Path(sys.argv[1])
for name in ('agent.py', 'web.py', 'telemetry.py', 'pam_auth.py', 'set_password.py', 'configure_mfa.py'):
    compile((root / name).read_text(), name, 'exec')
asset = root / 'assets' / 'ui-background.png'
if asset.stat().st_size > 4_000_000 or asset.read_bytes()[:8] != b'\x89PNG\r\n\x1a\n':
    raise SystemExit('Background asset is not a valid PNG within the 4 MB limit.')
print('Python source and PNG asset: OK')
PY
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s "$SRC/tests" -v

printf '\nInstalling the WebAuthn runtime dependency...\n'
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y python3-fido2
/usr/bin/python3 -c 'from fido2.server import Fido2Server; from fido2.webauthn import AttestedCredentialData, AuthenticatorData; print("python-fido2 WebAuthn runtime: OK")'

printf '\n[2/7] Backing up installed application and current theme...\n'
install -d -m 0700 "$BACKUP_DIR"
for file in agent.py web.py telemetry.py pam_auth.py index.html set_password.py configure_mfa.py VERSION; do
  if [[ -f "$APP_DIR/$file" ]]; then cp -a "$APP_DIR/$file" "$BACKUP_DIR/"; fi
done
if [[ -f "/etc/systemd/system/sbc-control-center-agent.service" ]]; then
  cp -a "/etc/systemd/system/sbc-control-center-agent.service" "$BACKUP_DIR/"
  UNIT_BACKUP=1
fi
if [[ -f "$APP_DIR/assets/ui-background.png" ]]; then
  install -d -m 0700 "$BACKUP_DIR/assets"
  cp -a "$APP_DIR/assets/ui-background.png" "$BACKUP_DIR/assets/"
  ASSET_BACKUP=1
fi

rollback() {
  UPGRADE_ACTIVE=0
  echo "Upgrade failed. Restoring previous portal application and theme..." >&2
  for file in agent.py web.py telemetry.py pam_auth.py index.html set_password.py configure_mfa.py VERSION; do
    if [[ -f "$BACKUP_DIR/$file" ]]; then
      cp -a "$BACKUP_DIR/$file" "$APP_DIR/$file" || true
    fi
  done
  if [[ "$ASSET_BACKUP" == "1" ]]; then
    install -d -m 0755 "$APP_DIR/assets"
    cp -a "$BACKUP_DIR/assets/ui-background.png" "$APP_DIR/assets/ui-background.png" || true
  else
    rm -f "$APP_DIR/assets/ui-background.png" || true
  fi
  if [[ "$UNIT_BACKUP" == "1" && -f "$BACKUP_DIR/sbc-control-center-agent.service" ]]; then
    cp -a "$BACKUP_DIR/sbc-control-center-agent.service" "/etc/systemd/system/sbc-control-center-agent.service" || true
  else
    rm -f "/etc/systemd/system/sbc-control-center-agent.service" || true
  fi
  systemctl daemon-reload || true
  systemctl restart sbc-control-center-agent.service sbc-control-center-web.service || true
}

on_error() {
  local rc=$?
  if [[ "$UPGRADE_ACTIVE" == "1" ]]; then rollback; fi
  exit "$rc"
}
trap on_error ERR

UPGRADE_ACTIVE=1
printf '\n[3/7] Installing application source...\n'
install -o root -g root -m 0755 "$SRC/agent.py" "$APP_DIR/agent.py"
install -o root -g root -m 0644 "$SRC/telemetry.py" "$APP_DIR/telemetry.py"
install -o root -g root -m 0644 "$SRC/pam_auth.py" "$APP_DIR/pam_auth.py"
install -o root -g root -m 0755 "$SRC/web.py" "$APP_DIR/web.py"
install -o root -g root -m 0644 "$SRC/index.html" "$APP_DIR/index.html"
install -o root -g root -m 0755 "$SRC/set_password.py" "$APP_DIR/set_password.py"
install -o root -g root -m 0755 "$SRC/configure_mfa.py" "$APP_DIR/configure_mfa.py"
install -o root -g root -m 0644 "$SRC/VERSION" "$APP_DIR/VERSION"
install -d -m 0755 /etc/systemd/system/sbc-control-center-web.service.d
cat > /etc/systemd/system/sbc-control-center-web.service.d/10-passkeys.conf <<EOF
[Service]
Environment=PORTAL_WEBAUTHN_RP_ID=${PORTAL_HOSTNAME}
EOF
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
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK
SystemCallArchitectures=native
ReadWritePaths=/etc/sbc-control-center /var/lib/sbc-control-center /run/sbc-control-center -/etc/hostapd -/etc/dnsmasq.d -/etc/apguard.nft -/etc/systemd/system/ap-iface.service -/etc/systemd/system/ap2-iface.service -/etc/systemd/system/apguard.service -/etc/systemd/system/hostapd-2g.service -/etc/systemd/system/multi-user.target.wants
[Install]
WantedBy=multi-user.target
EOF
install -d -o sbc-control-center -g sbc-control-center -m 0700 /var/lib/sbc-control-center-web
if [[ ! -s /etc/sbc-control-center/privilege.json ]]; then
  echo "Missing /etc/sbc-control-center/privilege.json. Re-run install.sh with SUDO_AUTH_USER set to a sudo-capable Linux account." >&2
  exit 1
fi

printf '\n[4/7] Installing global UI background asset...\n'
install -d -o root -g root -m 0755 "$APP_DIR/assets"
install -o root -g root -m 0644 "$SRC/assets/ui-background.png" "$APP_DIR/assets/ui-background.png"

printf '\n[5/7] Compiling Python application...\n'
if ! python3 -m py_compile "$APP_DIR/agent.py" "$APP_DIR/web.py" "$APP_DIR/set_password.py" "$APP_DIR/configure_mfa.py"; then
  rollback
  exit 1
fi

printf '\n[6/7] Restarting Control Center services...\n'
if ! systemctl daemon-reload; then
  rollback
  exit 1
fi
if ! systemctl restart sbc-control-center-agent.service sbc-control-center-web.service; then
  rollback
  exit 1
fi
sleep 2
if ! systemctl is-active --quiet sbc-control-center-agent.service || ! systemctl is-active --quiet sbc-control-center-web.service; then
  rollback
  exit 1
fi

printf '\n[7/7] Verifying local HTTPS and theme asset...\n'
code="$(curl -k -sS -o /dev/null -w '%{http_code}' --max-time 8 https://127.0.0.1:8443/ || true)"
asset_code="$(curl -k -sS -o /dev/null -w '%{http_code}' --max-time 8 https://127.0.0.1:8443/assets/ui-background.png || true)"
if [[ "$code" != "200" || "$asset_code" != "200" ]]; then
  echo "Health check failed: portal HTTP ${code:-none}; theme asset HTTP ${asset_code:-none}." >&2
  rollback
  exit 1
fi

cat <<EOF

SBC Control Center v0.0.1-1 installed successfully.
Portal health check: HTTP ${code}
Theme asset check: HTTP ${asset_code}
Previous application backup: ${BACKUP_DIR}

Preserved:
  - administrator password hash, TOTP enrollment and MFA replay state
  - HTTPS certificate/private key and session signing key
  - GitHub update source configuration (if previously configured)
  - AP/firewall, DHCP, policy routing and WireGuard configuration

Next steps:
  1. Refresh the portal in your browser.
  2. Open Admin terminal and type help.
  3. Configure a public GitHub owner/repository in Updates to enable six-hour release checks.
  4. Open https://${PORTAL_HOSTNAME}:8443 with a trusted certificate to enrol passkeys.
  5. Keep TCP/8443 off public WAN port-forwarding.

The release checker retrieves metadata only. It does not install remote code.
EOF
UPGRADE_ACTIVE=0
trap - ERR
