# SBC Control Center

**Version:** `0.0.1-2`  
**Project:** [0xb0rn3/sbc-control-center](https://github.com/0xb0rn3/sbc-control-center)

SBC Control Center is a self-hosted web interface for monitoring and administering a small Linux microserver. It combines host telemetry, network status, service controls, a restricted diagnostic console, update checks, configuration backups and passkey-capable authentication in a responsive desktop/mobile interface.

> **Hardware validation:** the current project has been tested so far on the **KickPi K2B** running an Armbian/Debian 13 (Trixie)-based system. Other single-board computers and microservers have not yet been validated. Treat support for other hardware as experimental until tested and documented.

![SBC Control Center navigation center on desktop](docs/screenshots/navigation-center-desktop.png)

![SBC Control Center navigation center on mobile](docs/screenshots/navigation-center-mobile.png)

![SBC Control Center live telemetry on desktop](docs/screenshots/telemetry-desktop.png)

![SBC Control Center live telemetry on mobile](docs/screenshots/telemetry-mobile.png)

## Features in 0.0.1-2

- Security patch: hardened root-agent isolation, fail-closed PAM root-bypass detection, bounded privileged socket workers, one-second non-overlapping telemetry scheduling, and controlled transient apt execution.

- Responsive administration portal with desktop sidebar, searchable navigation center and compact mobile navigation.
- Live telemetry samples Linux `/proc` and `/sys` on a non-overlapping one-second schedule while the browser tab is visible (browser scheduling and request latency mean this is a target, not a hard real-time guarantee): total/per-core CPU utilization, available CPU frequencies, RAM and swap, board thermal sensors, disk read/write throughput, process count, load average, kernel PSI pressure, and per-interface RX/TX bytes/s, packets/s, errors and drops. It also reports GPU/NPU frequency or utilization when the board's DRM/devfreq driver exports those metrics. Desktop and mobile trend charts keep a rolling 60-second sample window and can be filtered by interface. The network view provides Wireshark-style traffic-rate visibility from kernel counters; it does not capture packet payloads, decode protocols or replace Wireshark/tcpdump.
- Two-radio `hostapd` access-point view and configuration workflow for the current tested router-style profile.
- Service status and explicitly allow-listed start/stop/restart operations.
- WireGuard tunnel status and allow-listed service controls.
- Admin diagnostic console with fixed argument arrays, bounded output and read-only commands. Root-only diagnostics request a fresh Linux sudo password. It is **not** an unrestricted shell.
- Debian package update checks and an optional GitHub Releases metadata checker. Release checks do not execute or install remote project code.
- Password login, TOTP support and WebAuthn passkey login. HTTPS is enforced: the application starts only with a valid certificate/key, serves TLS 1.2 or newer, has no plaintext HTTP listener, and sends HSTS on HTTPS responses. Passkeys require a trusted HTTPS origin and a stable DNS hostname.
- Timestamped configuration snapshots. Creating or downloading a backup, which can contain Wi-Fi credentials, requires fresh sudo-password verification.
- Dark, low-glare design with the project background artwork applied across the interface.

## Current platform and scope

The codebase currently targets a Debian-family Linux host and the network layout used in the KickPi K2B validation setup. Telemetry is best-effort: temperature, CPU frequency, GPU/NPU utilization and PSI are shown only when the board kernel and drivers export the relevant `/sys` or `/proc` interfaces. Missing hardware/driver interfaces are shown as unavailable rather than estimated. In particular, the network-management pages expect a two-radio access-point profile using:

- `hostapd` and its primary/secondary configuration files;
- `dnsmasq` lease information;
- an `nftables` table named `inet apguard` and the matching AP firewall/service conventions;
- a `wg-quick@<interface>` WireGuard service.

The installer detects existing `hostapd` interface/SSID settings and an existing WireGuard profile where possible. It exposes environment overrides for hardware and network-specific values. Monitoring functions based on Linux `/proc`, `/sys`, `ip`, `ss` and standard system tools may work on other SBCs, but that is not a claim of full cross-platform support.

**Do not run the installer on a production machine until you have reviewed `install.sh`, the network assumptions above and your existing firewall.** The installer may add an HTTPS portal allow rule to `/etc/apguard.nft` when that file exists. It does not provision a complete AP, DHCP, VPN or kill-switch configuration from scratch.

## Requirements

- Debian 13 / Trixie is the currently targeted OS. Other Debian-derived distributions are unverified.
- Python 3, systemd and root access for installation.
- `hostapd`, `dnsmasq`, `nftables`, `iproute2`, `iw`, WireGuard and the corresponding service/configuration files for the network-management features.
- `python3-fido2` for passkey functionality (installed by the installer on supported Debian repositories).
- A local DNS/mDNS name and a trusted HTTPS certificate for passkey use.

## Install

Clone the public repository and review the scripts before running them:

```bash
git clone https://github.com/0xb0rn3/sbc-control-center.git
cd sbc-control-center
less install.sh
less agent.py
less web.py
```

The installer uses existing `hostapd` and WireGuard configuration to detect interfaces and tunnel names where possible. Override the profile with environment variables when required:

```bash
sudo env \
  AP_IFACE=wlan1 \
  AP2_IFACE=wlan0 \
  AP_IP=10.50.0.1 \
  AP_SUBNET=10.50.0.0/24 \
  AP2_IP=10.60.0.1 \
  AP2_SUBNET=10.60.0.0/24 \
  VPN_INTERFACE=wg0 \
  PORTAL_HOSTNAME=sbc-control-center.local \
  bash install.sh
```

The values shown are example defaults, not detected facts about your network. Choose free subnets that do not overlap with your LAN/VPN and check the interface names before installing. The installer creates the portal administrator account and prompts you to set its password. Keep TCP/8443 on your trusted LAN; do not forward it from the public internet.

Open the portal at:

```text
https://sbc-control-center.local:8443
```

The installer creates a local self-signed certificate. Browsers must trust that certificate (or you must deploy a certificate from your local CA) to avoid browser warnings and enable passkeys. The hostname must resolve to the server's address. Passkeys are origin-bound and do not work when switching between hostnames and IP addresses. The portal deliberately does not expose an HTTP port or redirect: use the HTTPS URL directly.

## Authentication and passkeys

The portal supports administrator password login, optional TOTP and WebAuthn passkeys. Passkey enrollment/removal requires fresh administrator verification and TOTP when enabled. The server stores public credential material only; private keys remain in the platform authenticator or external security key. Challenges are short-lived and single-use, and credential storage is permission-restricted.

Set `PORTAL_HOSTNAME` at install time to the stable DNS name you will use from every device. Do not change the hostname after enrolling passkeys unless you intend to re-enroll them. Retain the password/TOTP recovery method.

## Updates

The Debian package update workflow is separate from the Control Center's GitHub release checker. To enable six-hour metadata checks, open **Updates** and set the release source to:

```text
0xb0rn3/sbc-control-center
```

The project should publish GitHub Releases with numeric version tags such as `v0.0.1-1` or `v0.0.2`. Numeric revision suffixes are compared as revisions. The checker retrieves release metadata only. It does not download, execute or install code. Review a release and update manually over SSH after verifying its contents.

## Privilege model and security audit notes

- The HTTPS web process runs as the dedicated `sbc-control-center` system account. If `web.py` is accidentally launched as root, it drops supplementary groups, GID and UID to that account before binding the listener. Launching it as an unrelated unprivileged account or with unexpected supplementary groups is rejected.
- The root-side local agent accepts Unix-socket requests only from the `sbc-control-center` UID using Linux `SO_PEERCRED`. It does not accept the root UID as a portal peer.
- Mutating/root-only actions, package operations, service management, Wi-Fi changes, reboot/shutdown, release-source changes, system journal reads, firewall-rule inspection, WireGuard console details and sensitive backup downloads require a fresh password check against the host PAM `sudo` policy. The check does not trust cached sudo timestamps or `NOPASSWD` rules. A short-lived, session-bound, single-use token is stored as a hash in memory, bound to the exact action and target, and expires after 120 seconds; failed checks are rate-limited by session and configured admin account.
- The privileged agent uses fixed executable paths, fixed argument arrays and allow-lists. No HTTP input is passed to a shell, `eval`, or an arbitrary command executor. The terminal remains restricted and read-only. Automatic dashboard polling does not run privileged firewall inspection or request listener process-owner details; those sensitive diagnostics are explicitly step-up gated.
- The backup-download route rejects the old direct GET path and opens archive files with `O_NOFOLLOW`, checks that they are regular files, and imposes a 64 MiB limit. Backups may still contain Wi-Fi credentials, so treat downloads as secrets and store them encrypted.
- A source review and automated tests cover the current portal/API/agent paths. This is not a formal penetration test, does not prove the absence of privilege-escalation vulnerabilities, and does not replace host OS security updates or a professional assessment. The root agent remains part of the trusted computing base.
- Keep the portal on a trusted local network; never expose TCP/8443 directly to the WAN. Enable TOTP, use a unique long administrator passphrase and keep the host patched.
- Read `SECURITY.md` and review `install.sh`, `upgrade.sh`, `agent.py`, `web.py` and `pam_auth.py` before production deployment.

## Tests

Run the unit tests from the project root:

```bash
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -v
bash -n install.sh upgrade.sh
python3 -m py_compile agent.py web.py set_password.py configure_mfa.py
```

Browser screenshots are in `docs/screenshots/`. CI runs the Python test suite, Python compilation and shell syntax validation on pushes and pull requests.

## License

MIT


## Network observability and timestamped telemetry

The network observability feature set is implemented as a backend-to-UI pipeline, not a browser-generated simulation:

- A privileged-agent-owned sampler reads Linux `/sys/class/net/*/statistics` independently of browser polling. It keeps a bounded 15-minute ring (900 nominal one-second samples) and serves incremental sequence cursors.
- Each sample carries UTC acquisition time, Unix nanoseconds, monotonic nanoseconds, actual elapsed interval, raw cumulative counters, byte/packet deltas, and rates computed as delta divided by the measured monotonic interval.
- Counter resets, first samples, missing physical interfaces and stale sampler state are represented as unavailable rather than fabricated zero traffic. Physical totals exclude common virtual, bridge, tunnel and stacked links where sysfs topology identifies them.
- Graph x-coordinates use backend acquisition timestamps. Network series use the network-counter read timestamp; CPU, memory and other host series use their own sample timestamp. Tooltips show local time and UTC.
- The client inventory combines configured AP DHCP leases, kernel neighbour entries and Wi-Fi station information. IEEE OUI attribution is suppressed for locally administered/randomized MAC addresses.
- Active ARP discovery and per-client Nmap fingerprinting are restricted to the configured private AP networks and require fresh administrator verification.
- Packet capture is an explicit AF_PACKET operation on a configured interface allowlist. Metadata-only capture is the default; full PCAPNG is separately opted into, restricted to a root-owned private directory, and capped at 300 seconds / 32 MiB.
- TShark is used only for bounded offline analysis of completed application-owned captures. Packet payloads are not returned by the normal event API.
- DNS bypass signals are evidence indicators. A packet observed before AP DNAT is not proof that an external resolver was reached or that filtering was bypassed.
- AdGuard Home integration is optional and read-only in this release: local status and bounded query-log inspection. It does not automatically rewrite firewall rules, DHCP settings or resolver profiles.

### Installation dependencies

The installer installs `arp-scan`, `nmap`, `tshark`, `p0f`, `arpwatch`, `avahi-utils` and `ieee-data` alongside the base portal dependencies. Optional tools are reported as unavailable when missing. AF_PACKET requires Linux and the privileged agent's CAP_NET_RAW capability.

### Measurement boundaries

Interface byte rates are aggregate kernel-counter deltas over measured intervals. They are not per-packet or per-byte timestamps. Packet events use the kernel receive timestamp when SO_TIMESTAMPNS is available and otherwise use the userspace receive time. Capture length is the L3 packet size exposed by AF_PACKET SOCK_DGRAM, not an Ethernet wire-length counter. Wi-Fi monitor-mode management/control frames are not enabled automatically.
