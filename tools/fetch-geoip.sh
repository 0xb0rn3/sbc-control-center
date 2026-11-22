#!/usr/bin/env bash
# fetch-geoip.sh: the DB-IP City Lite database (CC BY 4.0, https://db-ip.com) for the threat map
# and the incident view. Monthly file; the newest available month is used. Locations are looked
# up locally: no address is ever sent anywhere. The map credits DB-IP as the licence requires.
set -euo pipefail
[ "$(id -u)" = 0 ] || { echo "run as root" >&2; exit 1; }
dir=/usr/share/GeoIP; tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
for month in "$(date -u +%Y-%m)" "$(date -u -d '-1 month' +%Y-%m)"; do
  if curl -fsSL --max-time 300 -o "$tmp/db.mmdb.gz" "https://download.db-ip.com/free/dbip-city-lite-$month.mmdb.gz"; then
    gunzip -t "$tmp/db.mmdb.gz" && gunzip "$tmp/db.mmdb.gz"
    python3 -c 'import maxminddb,sys; r=maxminddb.open_database(sys.argv[1]); assert r.get("1.1.1.1")' "$tmp/db.mmdb"
    install -d -m 0755 "$dir"
    install -m 0644 "$tmp/db.mmdb" "$dir/DB-IP-City-Lite.mmdb"
    ln -sfn "$dir/DB-IP-City-Lite.mmdb" "$dir/GeoLite2-City.mmdb"
    echo "DB-IP City Lite $month installed"; exit 0
  fi
done
echo "could not download DB-IP City Lite" >&2; exit 1
