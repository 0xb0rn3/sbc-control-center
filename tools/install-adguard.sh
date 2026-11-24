#!/usr/bin/env bash
# install-adguard.sh: the latest stable AdGuard Home for this machine's architecture, installed
# only when the archive matches the SHA-256 digest GitHub publishes for the release asset.
set -euo pipefail
[ "$(id -u)" = 0 ] || { echo "run as root" >&2; exit 1; }
case "$(uname -m)" in aarch64) arch=arm64;; armv7l) arch=armv7;; x86_64) arch=amd64;; *) echo "unsupported architecture" >&2; exit 1;; esac
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
python3 - "$tmp/release.json" "$arch" <<'PY'
import json, sys, urllib.request
req = urllib.request.Request('https://api.github.com/repos/AdguardTeam/AdGuardHome/releases/latest',
                             headers={'Accept': 'application/vnd.github+json', 'User-Agent': 'SBCControlCenter'})
data = json.load(urllib.request.urlopen(req, timeout=25))
if data.get('draft') or data.get('prerelease'):
    raise SystemExit('the latest release is not a stable release')
name = f'AdGuardHome_linux_{sys.argv[2]}.tar.gz'
asset = next((a for a in data.get('assets', []) if a.get('name') == name), None)
digest = (asset or {}).get('digest') or ''
if not asset or not digest.startswith('sha256:') or len(digest) != 71:
    raise SystemExit(f'{name} has no published SHA-256 digest; refusing an unverified binary')
json.dump({'tag': data['tag_name'], 'url': asset['browser_download_url'], 'sha': digest[7:]}, open(sys.argv[1], 'w'))
print('AdGuard Home', data['tag_name'])
PY
url=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["url"])' "$tmp/release.json")
sha=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["sha"])' "$tmp/release.json")
curl -fL --retry 3 --max-time 180 -o "$tmp/agh.tar.gz" "$url"
echo "$sha  $tmp/agh.tar.gz" | sha256sum -c -
mapfile -t entries < <(tar -tzf "$tmp/agh.tar.gz" | awk '$0 !~ /\/$/ && $0 ~ /(^|\/)AdGuardHome$/')
[ "${#entries[@]}" = 1 ] || { echo "expected exactly one AdGuardHome binary in the archive" >&2; exit 1; }
tar -xOzf "$tmp/agh.tar.gz" "${entries[0]}" > "$tmp/AdGuardHome.bin"
[ -s "$tmp/AdGuardHome.bin" ] || { echo "the AdGuardHome binary is empty" >&2; exit 1; }
getent group adguardhome >/dev/null || groupadd --system adguardhome
getent passwd adguardhome >/dev/null || useradd --system --gid adguardhome --home-dir /var/lib/AdGuardHome --shell /usr/sbin/nologin adguardhome
install -d -m 0755 /opt/AdGuardHome
install -m 0755 "$tmp/AdGuardHome.bin" /opt/AdGuardHome/AdGuardHome
install -d -o adguardhome -g adguardhome -m 0750 /etc/AdGuardHome /var/lib/AdGuardHome
echo "installed /opt/AdGuardHome/AdGuardHome"
