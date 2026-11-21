# Security policy

SBC Control Center manages privileged host and network functions. It requires HTTPS and must not be exposed directly to the public internet. The server refuses startup without a certificate and private key, negotiates TLS 1.2 or newer, disables TLS compression, and emits HSTS on TLS responses. There is no plaintext HTTP listener or HTTP redirect path.

## Reporting a vulnerability

Please report security issues privately through GitHub's **Report a vulnerability** feature (Security Advisories) when enabled for this repository. Include the affected version, impact, reproducible steps and any suggested mitigation. Do not publish working exploit details in a public issue before a fix is available.

## Privileged architecture

- `web.py` serves authenticated requests as the dedicated `sbc-control-center` user. If started as root, it drops groups/GID/UID before opening the listener, and rejects unexpected supplementary groups. It refuses to run as any unrelated account.
- `agent.py` is a separate root service with a Unix-domain socket. It verifies `SO_PEERCRED` and accepts only the dedicated portal UID.
- Root-only actions require a fresh Linux PAM authentication against the `sudo` service. `sudo` timestamps and `NOPASSWD` shortcuts are not accepted as proof of the user's password.
- The resulting authorization is a single-use token, bound to the authenticated portal session and a canonical digest of the exact action/target/payload, expired after 120 seconds, and stored as a hash in agent memory. A service restart grant cannot be replayed as a reboot or against another service; the Wi-Fi passphrase contributes only to the digest and is not stored in the grant. Attempts are rate-limited by both portal session and configured sudo account.
- The privileged agent systemd unit uses a strict read-only filesystem view, kernel/control-group protections, SUID/SGID restrictions, a native syscall architecture, and a restricted address-family list. Writable paths are limited to the portal configuration/state/runtime directories and the specific host AP/firewall/service configuration locations required by the allow-listed actions. Optional host paths are marked optional so absent components do not prevent startup.
- The long-lived agent does not gain broad apt/dpkg write access. The three fixed package-manager operations run as separate transient systemd services only after the existing fresh-password, single-use authorization check; timeout handling stops the transient unit. Package maintainer scripts still execute as root as part of a user-approved OS update, which is inherent to package installation.
- The root agent accepts at most eight concurrent portal socket workers. Additional connections receive a bounded busy response; each accepted request has a socket timeout and a 16 KiB request cap.
- PAM step-up checks the `sudo` PAM include/substack graph before invoking PAM and fails closed if `pam_rootok.so` is present or the stack cannot be inspected. This avoids the root-process authentication shortcut. Validate the actual target host's PAM files during deployment, especially when custom PAM includes are used.
- The agent uses fixed command arrays and explicit service/action allow-lists. Sensitive diagnostic reads (including nftables rule inspection, journal access, WireGuard console details and listener process ownership) are step-up protected. Automatic dashboard listener summaries omit process ownership; automatic polling does not execute nftables inspection. Do not add shell execution, arbitrary commands, dynamic unit names or unvalidated filesystem paths.
- Backup download requests require step-up authentication and use no-follow file opening. Archives contain sensitive configuration and may contain WLAN keys.

## Audit scope and limitations

The project includes source-level checks and automated tests for HTTPS-only startup and HSTS, HTTP session controls, passkey challenge binding, allow-listed agent commands, peer credentials, PAM step-up, one-use tokens, backup path handling, kernel telemetry parsing and rate calculations, bounded agent concurrency, PAM root-bypass detection and installer service sandbox settings. This is not a formal penetration test, and automated tests cannot establish that a system is free of privilege-escalation vulnerabilities. The root agent remains security-critical. Keep it small, review changes before installing, restrict network access and keep the host OS patched.

## Deployment guidance

- Restrict access to trusted LAN/VPN segments; do not port-forward TCP/8443.
- Enable TOTP, use a unique long administrator passphrase and retain recovery access.
- Trust the local HTTPS certificate (or install a certificate from your own local CA) and use a stable DNS name for WebAuthn passkeys. Do not proxy the application over plaintext HTTP.
- Keep backups encrypted and access-controlled.
- Review changes to `install.sh`, `upgrade.sh`, `agent.py`, `web.py` and `pam_auth.py` before deployment.


## Network telemetry and packet capture

Network observability is sensitive administrative data. Keep the HTTPS portal on trusted management networks and do not expose it directly to the public internet.

- Passive telemetry reads kernel counters and local network metadata. It is collected by the privileged agent and stored in a bounded in-memory ring; browser requests only read samples and cannot reset the sampling clock.
- Device inventory can contain private IP addresses, MAC addresses, DHCP hostnames, SSIDs, DNS names and inferred device categories. These records must not be uploaded to public issue trackers or included in diagnostic bundles without explicit review.
- Active ARP discovery, Nmap fingerprinting, packet capture and local device-label changes require fresh sudo-password verification and are scoped to configured AP interfaces/networks.
- Packet capture defaults to metadata-only mode. Full PCAPNG requires a separate explicit option, is restricted to root-owned mode-0600 files, and is bounded to 300 seconds and 32 MiB. Captures can contain sensitive traffic metadata and must be deleted when no longer required.
- The standard event API never returns packet payloads. TShark analysis is limited to completed private capture files, a fixed field list, 5,000 packets, 15 seconds and bounded output.
- DNS endpoint matches and direct-DNS packets are indicators, not proof of successful bypass. Enforcement outcomes remain unknown unless independently verified by firewall counters/traces or resolver logs.
- AdGuard credentials, if configured, belong in a root-owned mode-0600 `/etc/sbc-control-center/dns.json` file and must never be committed. The optional integration only reads local AdGuard status/query logs in this release.
- The agent systemd unit allows AF_PACKET and CAP_NET_RAW only for the privileged agent. Do not grant packet-capture capabilities to the unprivileged web process.
