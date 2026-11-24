"""Intrusion detection with Suricata on both access points, and its alerts for the threat map.

Suricata (Debian package) watches the two access-point interfaces with the Emerging Threats Open
rules (free, about 50 000 enabled), updated daily by suricata-update. It only watches and logs
(IDS): nothing is blocked. Alerts go to Suricata's eve.json; this module reads the recent ones
for the threat map and the incidents list.

  python3 ids.py install-units   # root: point Suricata at the access points, add the daily rule update
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from collections import Counter
from pathlib import Path
from typing import Any

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import sbc_site  # noqa: E402

SITE = sbc_site.load()
EVE = Path('/var/log/suricata/eve.json')
DROPIN = Path('/etc/systemd/system/suricata.service.d/50-sbc-ids.conf')
EVE_ALERTS = Path('/etc/suricata/sbc-eve-alerts.yaml')
# Suricata's outputs, alerts only (an --include replaces the stock outputs list). The stock config also
# logs every flow, DNS lookup, QUIC/TLS name, HTTP request and stats line: 99% of eve.json, read by
# nothing here, and the household's browsing history. On Armbian /var/log is a 50 MB RAM disk: that
# filled it in about a day, every other log there failed to write, and Armbian's truncate job copied
# the whole disk to the flash every 15 minutes trying to make room.
EVE_ALERTS_TEXT = """%YAML 1.1
---
# SBC Control Center (ids.py): alerts only. See ids.py for why.
outputs:
  - fast:
      enabled: yes
      filename: fast.log
      append: yes
  - eve-log:
      enabled: yes
      filetype: regular
      filename: eve.json
      types:
        - alert:
            tagged-packets: yes
"""
RULES_UNIT = f'{sbc_site.PREFIX}-ids-rules'
TAIL_BYTES = 4 * 1024 * 1024
_rules_cache: dict[str, Any] = {'mtime': None, 'enabled': 0}


def dropin_text(cfg: dict[str, str] | None = None) -> str:
    cfg = cfg or SITE
    ifaces = ' '.join(f'-i {i}' for i in sbc_site.ap_interfaces(cfg))
    home = ','.join(sbc_site.ap_subnets(cfg))
    return f"""# SBC Control Center: watch the access points (IDS only, nothing is blocked)
[Service]
ExecStart=
ExecStart=/usr/bin/suricata -D -c /etc/suricata/suricata.yaml --include {EVE_ALERTS} --pidfile /run/suricata.pid {ifaces} --set vars.address-groups.HOME_NET=[{home}] --set detect.profile=low --set detect.sgh-mpm-context=single --set mpm-algo=ac-bs
# low-memory matching: the full ET Open set otherwise needs more than 1 GB on a small board
MemoryHigh=1200M
MemoryMax=1600M
# /var/log is in memory on Armbian: let systemd create Suricata's log folder at every start
LogsDirectory=suricata
Nice=5
Restart=on-failure
RestartSec=30
"""


def rules_units() -> tuple[str, str]:
    service = """[Unit]
Description=Update the Suricata rules (Emerging Threats Open) and reload them

[Service]
Type=oneshot
ExecStart=/usr/bin/suricata-update --no-test
ExecStartPost=-/usr/bin/systemctl reload suricata.service
Nice=15
IOSchedulingClass=idle
"""
    timer = """[Unit]
Description=Daily Suricata rule update

[Timer]
OnCalendar=*-*-* 04:20
RandomizedDelaySec=45min
Persistent=true

[Install]
WantedBy=timers.target
"""
    return service, timer


def install_units() -> None:
    if os.geteuid() != 0:
        raise SystemExit('run as root')
    EVE_ALERTS.write_text(EVE_ALERTS_TEXT)
    # the merged config must parse before Suricata is pointed at it
    check = subprocess.run(['/usr/bin/suricata', '-c', '/etc/suricata/suricata.yaml', '--include', str(EVE_ALERTS), '--dump-config'],
                           capture_output=True, text=True, timeout=120)
    if check.returncode != 0 or 'outputs.1.eve-log.types.0 = alert' not in check.stdout:
        raise SystemExit(f'suricata does not accept {EVE_ALERTS}: {(check.stderr or check.stdout).strip()[-300:]}')
    DROPIN.parent.mkdir(parents=True, exist_ok=True)
    DROPIN.write_text(dropin_text())
    service, timer = rules_units()
    Path(f'/etc/systemd/system/{RULES_UNIT}.service').write_text(service)
    Path(f'/etc/systemd/system/{RULES_UNIT}.timer').write_text(timer)
    subprocess.run(['systemctl', 'daemon-reload'], check=True)
    subprocess.run(['systemctl', 'reset-failed', 'suricata.service'], check=False)
    subprocess.run(['systemctl', 'enable', '--now', f'{RULES_UNIT}.timer'], check=True)
    subprocess.run(['systemctl', 'enable', 'suricata.service'], check=True)
    os.sync()
    subprocess.run(['systemctl', 'restart', 'suricata.service'], check=True)
    print(f"suricata watching {', '.join(sbc_site.ap_interfaces(SITE))}; rules update daily ({RULES_UNIT}.timer)")


def _tail_lines(path: Path, max_bytes: int = TAIL_BYTES) -> list[str]:
    try:
        with path.open('rb') as handle:
            handle.seek(0, os.SEEK_END)
            size = handle.tell()
            handle.seek(max(0, size - max_bytes))
            data = handle.read()
    except OSError:
        return []
    lines = data.decode('utf-8', 'replace').splitlines()
    return lines[1:] if size > max_bytes else lines


def alerts(hours: int = 24, limit: int = 200) -> list[dict[str, Any]]:
    since = time.time() - hours * 3600
    out = []
    for line in _tail_lines(EVE):
        if '"alert"' not in line:   # cheap pre-filter; the parsed event type decides
            continue
        try:
            ev = json.loads(line)
        except ValueError:
            continue
        if ev.get('event_type') != 'alert':
            continue
        stamp = ev.get('timestamp', '')
        try:
            t = time.mktime(time.strptime(stamp[:19], '%Y-%m-%dT%H:%M:%S'))
        except ValueError:
            continue
        if t < since:
            continue
        a = ev.get('alert') or {}
        out.append({'time': int(t), 'src_ip': ev.get('src_ip'), 'src_port': ev.get('src_port'),
                    'dest_ip': ev.get('dest_ip'), 'dest_port': ev.get('dest_port'), 'proto': ev.get('proto'),
                    'iface': ev.get('in_iface'), 'signature': str(a.get('signature', ''))[:160],
                    'category': str(a.get('category', ''))[:80], 'severity': a.get('severity'),
                    'sid': a.get('signature_id')})
    return out[-limit:][::-1]


def status() -> dict[str, Any]:
    active = subprocess.run(['/usr/bin/systemctl', 'is-active', '--quiet', 'suricata.service'], timeout=3).returncode == 0
    recent = alerts()
    rules = Path('/var/lib/suricata/rules/suricata.rules')
    try:
        rules_at = int(rules.stat().st_mtime)
        if _rules_cache['mtime'] != rules_at:   # count the enabled rules once per update
            _rules_cache.update(mtime=rules_at, enabled=sum(1 for line in rules.open(errors='replace') if line.startswith('alert')))
        enabled = _rules_cache['enabled']
    except OSError:
        enabled, rules_at = 0, None
    return {'ok': True, 'running': active, 'rules_enabled': enabled, 'rules_updated': rules_at,
            'interfaces': sbc_site.ap_interfaces(SITE), 'alerts': recent,
            'top_signatures': Counter(a['signature'] for a in recent).most_common(8)}


if __name__ == '__main__':
    if (sys.argv[1:] or [''])[0] == 'install-units':
        install_units()
    else:
        raise SystemExit(__doc__)
