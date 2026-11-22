#!/usr/bin/env bash
# install-dependencies.sh [--all]: everything the Control Center's components need on Debian 13 / Armbian.
#   packages/debian-required.txt   always
#   packages/debian-optional.txt   with --all (Suricata intrusion detection)
# plus the two pieces Debian does not package: AdGuard Home (tools/install-adguard.sh) and the
# DB-IP City Lite location database (tools/fetch-geoip.sh). Run as root.
set -euo pipefail
here=$(cd "$(dirname "$0")/.." && pwd)
[ "$(id -u)" = 0 ] || { echo "run as root" >&2; exit 1; }
lists=("$here/packages/debian-required.txt")
[ "${1:-}" = "--all" ] && lists+=("$here/packages/debian-optional.txt")
mapfile -t pkgs < <(sed 's/#.*//' "${lists[@]}" | awk 'NF{print $1}')
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "${pkgs[@]}"
[ -x /opt/AdGuardHome/AdGuardHome ] || "$here/tools/install-adguard.sh"
[ -f /usr/share/GeoIP/GeoLite2-City.mmdb ] || "$here/tools/fetch-geoip.sh"
echo "all dependencies are installed"
