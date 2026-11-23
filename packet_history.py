"""24-hour packet history: an always-on header capture kept on a ring, plus a host table.

The recorder (dumpcap, in its own sandboxed service with only the capture capabilities) writes
packet headers from both access points and the uplink into hour-long files. The 24 newest
are kept and the oldest is deleted first; a size cap per file bounds the disk use, so under
heavy traffic the history covers less than 24 hours rather than filling the disk (the page shows
the real coverage). Only headers are kept (the first 128 bytes of each packet): addresses,
ports, timing and sizes, not content. The uplink capture leaves out the VPN tunnel's own
encrypted transport, which would only duplicate the access-point traffic.

Every closed hour is summarised once, at low priority: each hardware address seen, its IP
addresses, first and last time, packets and bytes. The host table joins those hours and marks
any address that is not a known device (DHCP lease, a labelled device, this board, the
uplink router) as unrecognised: a device that should not be there, or one that never asked
for an address, shows up there within the hour.

  python3 packet_history.py install-units   # root: write the recorder and summary units
  python3 packet_history.py summarize       # what the summary timer runs
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

# run with python3 -I (no script folder on the path): import the neighbours from the install folder
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import sbc_site  # noqa: E402

SITE = sbc_site.load()
UNIT = f'{sbc_site.PREFIX}-packet-history'
SUMMARY_UNIT = f'{UNIT}-summary'
HISTORY_DIR = Path('/var/lib') / f'{sbc_site.NAME}-history'
SUMMARY_DIR = sbc_site.STATE_DIR / 'history-summaries'
FILES_KEPT = 24
FILE_SECONDS = 3600
FILE_MAX_KB = 100 * 1024        # 24 x 100 MB = at most 2.4 GB on disk
SNAPLEN = 128
TSHARK = '/usr/bin/tshark'
DUMPCAP = '/usr/bin/dumpcap'
RING = re.compile(r'ring_([0-9]{5})_([0-9]{14})\.pcapng')
WG_PORT = 51820


def capture_interfaces(cfg: dict[str, str] | None = None) -> list[tuple[str, str]]:
    """(interface, capture filter) pairs: both access points whole, the uplink without the tunnel."""
    cfg = cfg or SITE
    return [(cfg['ap2_interface'], ''), (cfg['ap_interface'], ''),
            (cfg['uplink_interface'], f'not udp port {WG_PORT}')]


def unit_text(cfg: dict[str, str] | None = None) -> str:
    args = []
    for iface, capture_filter in capture_interfaces(cfg):
        args += ['-i', iface] + (['-f', f"'{capture_filter}'"] if capture_filter else [])
    return f"""[Unit]
Description=24-hour packet header history (ring of {FILES_KEPT} hour files)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
DynamicUser=yes
StateDirectory={HISTORY_DIR.name}
StateDirectoryMode=0700
AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN
CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictAddressFamilies=AF_PACKET AF_NETLINK AF_UNIX AF_INET AF_INET6
RestrictSUIDSGID=yes
LockPersonality=yes
MemoryMax=192M
Nice=10
IOSchedulingClass=best-effort
IOSchedulingPriority=7
ExecStart={DUMPCAP} -q -n -s {SNAPLEN} {' '.join(args)} -b duration:{FILE_SECONDS} -b filesize:{FILE_MAX_KB} -b files:{FILES_KEPT} -w %S/{HISTORY_DIR.name}/ring.pcapng
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
"""


def summary_units() -> tuple[str, str]:
    app = sbc_site.APP_DIR
    service = f"""[Unit]
Description=Summarise closed packet-history hours (hosts, first/last seen)

[Service]
Type=oneshot
ExecStart=/usr/bin/python3 -I {app}/packet_history.py summarize
Nice=19
IOSchedulingClass=idle
CPUQuota=60%
MemoryMax=256M
PrivateNetwork=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
NoNewPrivileges=yes
ReadWritePaths={sbc_site.STATE_DIR}
"""
    timer = f"""[Unit]
Description=Summarise packet-history hours every 15 minutes

[Timer]
OnBootSec=5min
OnUnitActiveSec=15min
AccuracySec=1min

[Install]
WantedBy=timers.target
"""
    return service, timer


def install_units() -> None:
    if os.geteuid() != 0:
        raise SystemExit('run as root')
    unit_dir = Path('/etc/systemd/system')
    (unit_dir / f'{UNIT}.service').write_text(unit_text())
    service, timer = summary_units()
    (unit_dir / f'{SUMMARY_UNIT}.service').write_text(service)
    (unit_dir / f'{SUMMARY_UNIT}.timer').write_text(timer)
    SUMMARY_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.sync()   # flush before enabling: unflushed unit files can come back empty after a power cut
    subprocess.run(['systemctl', 'daemon-reload'], check=True)
    subprocess.run(['systemctl', 'enable', '--now', f'{UNIT}.service', f'{SUMMARY_UNIT}.timer'], check=True)
    print(f'{UNIT} recording {", ".join(i for i, _ in capture_interfaces())}; summaries every 15 min')


# ---------------------------------------------------------------- reading the ring

def ring_files() -> list[dict[str, Any]]:
    try:
        entries = [e for e in os.scandir(HISTORY_DIR) if e.is_file(follow_symlinks=False) and RING.fullmatch(e.name)]
    except OSError:
        return []
    files = []
    for e in entries:
        m = RING.fullmatch(e.name)
        started = time.mktime(time.strptime(m.group(2), '%Y%m%d%H%M%S'))
        st = e.stat(follow_symlinks=False)
        files.append({'name': e.name, 'seq': int(m.group(1)), 'started': int(started),
                      'modified': int(st.st_mtime), 'bytes': st.st_size})
    files.sort(key=lambda f: f['seq'])
    for i, f in enumerate(files):
        f['closed'] = i < len(files) - 1   # the newest file is still being written
    return files


def summarize_file(path: Path) -> dict[str, Any]:
    """Per hardware address: IPs, first/last seen, packets, bytes (eth/ip/arp layers only)."""
    cmd = [TSHARK, '-n', '-r', str(path), '--disable-protocol', 'ALL',
           '--enable-protocol', 'eth', '--enable-protocol', 'ip', '--enable-protocol', 'ipv6', '--enable-protocol', 'arp',
           '-T', 'fields', '-E', 'separator=,', '-e', 'frame.time_epoch', '-e', 'frame.len',
           '-e', 'eth.src', '-e', 'eth.dst', '-e', 'ip.src', '-e', 'ipv6.src', '-e', 'arp.src.proto_ipv4',
           '-e', 'frame.interface_name']
    hosts: dict[str, dict[str, Any]] = {}
    packets = 0
    with subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True) as proc:
        assert proc.stdout is not None
        for line in proc.stdout:
            f = line.rstrip('\n').split(',')
            if len(f) < 8:
                continue
            packets += 1
            try:
                t = float(f[0]); size = int(f[1] or 0)
            except ValueError:
                continue
            mac = f[2].lower()
            if not re.fullmatch(r'(?:[0-9a-f]{2}:){5}[0-9a-f]{2}', mac):
                continue
            h = hosts.get(mac)
            if h is None:
                h = hosts[mac] = {'first': t, 'last': t, 'packets': 0, 'bytes': 0, 'ips': set(), 'ifaces': set()}
            h['first'] = min(h['first'], t); h['last'] = max(h['last'], t)
            h['packets'] += 1; h['bytes'] += size
            for ip in (f[4], f[5], f[6]):
                if ip and len(h['ips']) < 16:
                    h['ips'].add(ip.split(',')[0])
            if f[7] and len(h['ifaces']) < 4:
                h['ifaces'].add(f[7])
    return {'packets': packets, 'hosts': {mac: {**h, 'ips': sorted(h['ips']), 'ifaces': sorted(h['ifaces'])}
                                          for mac, h in hosts.items()}}


def summarize() -> int:
    SUMMARY_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    done = 0
    names = set()
    for f in ring_files():
        names.add(f['name'])
        out = SUMMARY_DIR / (f['name'] + '.json')
        if not f['closed'] or out.exists():
            continue
        summary = summarize_file(HISTORY_DIR / f['name'])
        summary.update({'file': f['name'], 'started': f['started'], 'ended': f['modified'], 'made': int(time.time())})
        tmp = out.with_suffix('.tmp')
        tmp.write_text(json.dumps(summary, separators=(',', ':')))
        os.replace(tmp, out)
        done += 1
    for old in SUMMARY_DIR.glob('ring_*.json'):
        if old.name[:-5] not in names:   # its hour has left the ring
            old.unlink(missing_ok=True)
    return done


def _known_macs() -> dict[str, str]:
    """Addresses that belong here: DHCP leases, labelled devices, this board's own interfaces."""
    known: dict[str, str] = {}
    try:
        for line in Path(SITE['dhcp_lease_file']).read_text().splitlines():
            parts = line.split()
            if len(parts) >= 4:
                known[parts[1].lower()] = parts[3] if parts[3] != '*' else 'DHCP lease'
    except OSError:
        pass
    try:
        labels = json.loads((sbc_site.STATE_DIR / 'device-labels.json').read_text())
        for mac, value in (labels.items() if isinstance(labels, dict) else []):
            label = value.get('label') if isinstance(value, dict) else value
            known[str(mac).lower()] = str(label or 'labelled device')
    except (OSError, ValueError):
        pass
    try:
        for iface in os.listdir('/sys/class/net'):
            mac = Path(f'/sys/class/net/{iface}/address').read_text().strip().lower()
            if mac and mac != '00:00:00:00:00:00':
                known[mac] = f'this board ({iface})'
    except OSError:
        pass
    try:  # the uplink's default gateway: the home router
        route = subprocess.run(['/usr/sbin/ip', '-4', 'route', 'show', 'default', 'dev', SITE['uplink_interface']],
                               capture_output=True, text=True, timeout=3).stdout.split()
        gateway = route[route.index('via') + 1] if 'via' in route else ''
        neigh = subprocess.run(['/usr/sbin/ip', 'neigh', 'show', gateway], capture_output=True, text=True, timeout=3).stdout.split()
        if 'lladdr' in neigh:
            known[neigh[neigh.index('lladdr') + 1].lower()] = 'uplink router'
    except (OSError, ValueError, IndexError, subprocess.TimeoutExpired):
        pass
    return known


def status() -> dict[str, Any]:
    files = ring_files()
    active = subprocess.run(['/usr/bin/systemctl', 'is-active', '--quiet', f'{UNIT}.service'], timeout=3).returncode == 0
    hosts: dict[str, dict[str, Any]] = {}
    summarised = 0
    for f in files:
        try:
            data = json.loads((SUMMARY_DIR / (f['name'] + '.json')).read_text())
        except (OSError, ValueError):
            continue
        summarised += 1
        f['packets'] = data.get('packets')
        for mac, h in data.get('hosts', {}).items():
            agg = hosts.setdefault(mac, {'mac': mac, 'first': h['first'], 'last': h['last'], 'packets': 0, 'bytes': 0, 'ips': set(), 'ifaces': set(), 'hours': 0})
            agg['first'] = min(agg['first'], h['first']); agg['last'] = max(agg['last'], h['last'])
            agg['packets'] += h['packets']; agg['bytes'] += h['bytes']; agg['hours'] += 1
            agg['ips'].update(h.get('ips', [])); agg['ifaces'].update(h.get('ifaces', []))
    known = _known_macs()
    ap_ifaces = set(sbc_site.ap_interfaces(SITE))
    rows = []
    for mac, h in hosts.items():
        multicast = int(mac.split(':')[0], 16) & 1
        on_ap = bool(h['ifaces'] & ap_ifaces)
        label = known.get(mac)
        if label is None and not on_ap:
            # seen only on the uplink cable: a device of the home router's own network, not of these access points
            label = 'home router network'
        rows.append({**h, 'ips': sorted(h['ips'])[:8], 'ifaces': sorted(h['ifaces']),
                     'known': label, 'multicast': bool(multicast), 'on_access_point': on_ap,
                     'unrecognised': not multicast and on_ap and mac not in known})
    rows.sort(key=lambda r: (not r['unrecognised'], -r['last']))
    total = sum(f['bytes'] for f in files)
    return {
        'ok': True, 'unit': UNIT, 'recording': active, 'files': files, 'bytes': total,
        'budget_bytes': FILES_KEPT * FILE_MAX_KB * 1024, 'files_kept': FILES_KEPT,
        'oldest': files[0]['started'] if files else None, 'newest': files[-1]['modified'] if files else None,
        'interfaces': [i for i, _ in capture_interfaces()], 'snaplen': SNAPLEN,
        'summarised_hours': summarised, 'hosts': rows[:400],
        'unrecognised': sum(1 for r in rows if r['unrecognised']),
    }


if __name__ == '__main__':
    command = sys.argv[1] if len(sys.argv) > 1 else ''
    if command == 'install-units':
        install_units()
    elif command == 'summarize':
        print(f'summarised {summarize()} hour file(s)')
    else:
        raise SystemExit(__doc__)
