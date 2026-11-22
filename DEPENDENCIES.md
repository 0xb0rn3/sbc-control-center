# Dependencies

Everything a component needs, and where it comes from. On Debian 13 (trixie) or Armbian:

```sh
sudo tools/install-dependencies.sh          # required packages, AdGuard Home, DB-IP database
sudo tools/install-dependencies.sh --all    # plus the optional components (Suricata)
```

The package lists are in [`packages/debian-required.txt`](packages/debian-required.txt) and
[`packages/debian-optional.txt`](packages/debian-optional.txt).

| Component | Needs | From |
|---|---|---|
| Web portal, sign-in, passkeys, TOTP | `python3`, `python3-fido2`, `openssl`, `libpam0g`, `sudo` | Debian |
| Privileged agent, service control, backups | `python3`, `procps`, `util-linux`, `iproute2` | Debian |
| Access points and DHCP | `hostapd`, `dnsmasq`, `iw` | Debian |
| Firewall, kill switch, policy routing | `nftables`, `iproute2` | Debian |
| VPN tunnel, server library, rotation | `wireguard-tools`, `curl` | Debian; server list from Mullvad's public relay list |
| DNS filtering profiles | AdGuard Home, `python3-yaml` | `tools/install-adguard.sh` (GitHub release, SHA-256 checked) |
| Live telemetry | kernel `/proc` and `/sys` only | |
| Live packet inspector, packet forensics | `tshark`, `tcpdump` | Debian |
| 24-hour packet history | `tshark` (dumpcap, capinfos) | Debian |
| Device discovery and fingerprints | `arp-scan`, `nmap`, `p0f`, `arpwatch`, `ieee-data`, `avahi-utils` | Debian |
| Live threat map, incidents, reputation | `conntrack`, `python3-maxminddb`, `python3-geoip2`, `curl` | Debian; DB-IP City Lite via `tools/fetch-geoip.sh`; feeds below |
| Intrusion detection (optional) | `suricata`, `suricata-update` | Debian; Emerging Threats Open rules (daily) |
| Root terminal | `bash`, `systemd` (transient units) | Debian |
| Living room, slideshow | wallpapers you supply (`tools/load-wallpapers.sh` needs ImageMagick 7 and `rsync` on your computer) | |
| Quote fonts (rebuild only) | `fontTools`, `brotli` and the Noto fonts on your computer (`tools/build-quote-fonts.py`) | PyPI, Noto (SIL OFL 1.1) |

Bundled in this repository: xterm.js 5.5.0 and its fit addon (MIT, `assets/vendor/`), Noto glyph
subsets for the quotes (SIL OFL 1.1, `assets/ui/NOTO-FONTS-LICENSE.txt`), the Natural Earth
1:110m land outline (public domain, `assets/ui/world.svg`).

Fetched at run time, all public and keyless, through the VPN tunnel where the board has one:

| Data | Source |
|---|---|
| VPN server list | Mullvad public relay list, `api.mullvad.net/www/relays/wireguard/` |
| Top attacking addresses | SANS ISC DShield API |
| Botnet command servers | abuse.ch Feodo Tracker |
| Hijacked networks | Spamhaus DROP |
| Recently reported attackers | blocklist.de |
| Malware and phishing hosts | malware-filter project (URLhaus and phishing lists) |
| IP geolocation | DB-IP City Lite, monthly, CC BY 4.0: the map shows "IP Geolocation by DB-IP" |
| IDS rules | Emerging Threats Open, via `suricata-update` |

Each source has its own terms of use; read them before using the data for anything beyond a
home network.

Not packaged by Debian and left optional: Zeek (would need a third-party package repository).
