## Security hardening patch (0.0.1-2)

- Hardened the privileged agent with systemd filesystem, kernel, syscall-architecture, and address-family restrictions plus narrowly scoped writable paths.
- Bounded privileged-agent socket workers and added a fail-fast busy response to prevent unbounded thread creation.
- Added fail-closed PAM include-graph inspection to reject `pam_rootok.so` in the sudo authentication stack.
- Changed telemetry to non-overlapping recursive 1-second polling, paused while the page is hidden.
- Added regression tests for PAM root-bypass detection.
- Kept the long-lived root agent sandboxed while routing the three fixed, explicitly authorized apt operations through a transient systemd service; timeout handling stops the transient unit instead of granting the agent broad apt/dpkg filesystem write access.

# Changelog

## 0.0.1-1 - Live telemetry and privilege hardening

- Added continuous Linux kernel telemetry: total/per-core CPU, optional CPU frequency and GPU/NPU utilization, RAM/swap, thermal sensors, disk I/O, load, PSI pressure, process count, and interface byte throughput, packets/s, errors and drops.
- Added rolling 60-second desktop/mobile charts for CPU, memory, network bytes, packet rate, disk I/O and temperature.
- Added a PAM-backed fresh sudo-password step-up for service changes, package operations, Wi-Fi configuration, reboot/shutdown, system journal access and sensitive backup downloads.
- Added account-wide and per-session privilege verification throttling with short-lived, session-bound, single-use authorization tokens bound to the exact approved action and target.
- The web portal drops to the dedicated unprivileged service account if started as root, rejects unexpected supplementary groups, and the root agent accepts only that account over its Unix socket.
- Hardened backup delivery against symlinks and unbounded file reads. Automatic dashboard polling no longer requests privileged firewall rules or listener process ownership.
- Enforced TLS 1.2+ with no plaintext HTTP listener, disabled TLS compression and added HSTS on HTTPS responses.
- Improved the update checker's numeric release comparison for `0.0.1-1` revision tags.
- Added refreshed desktop and mobile telemetry preview screenshots with synthetic values clearly marked as examples.

## 0.0.1 - Initial public release

- Published the project as **SBC Control Center**.
- Removed private home-server labels, SSIDs, interface MAC identifiers and local host addresses from public defaults.
- Added generic hostname, access-point interface/SSID and WireGuard profile configuration.
- Retained the responsive navigation center for desktop and mobile.
- Included desktop and mobile navigation-center screenshots under `docs/screenshots/`.
- Documented the current validation boundary: KickPi K2B only, on an Armbian/Debian 13-based system.
- Included passkey authentication, TOTP/password recovery, a restricted diagnostic console, service allow-lists, configuration backups and metadata-only release checks.
