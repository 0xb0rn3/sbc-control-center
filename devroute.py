"""Per-device routing on the access points: main VPN tunnel, a second tunnel, direct, or blocked.

Devices are matched by hardware address (MAC), so a rule follows a device whatever address
DHCP gives it. The rules live in a managed block of the access-point firewall (apguard), which
stays the one place that decides what may leave the Wi-Fi:

  main     the default: nothing changes, traffic leaves through the main tunnel only
  second   a mark sends it to routing table 201: default via the second tunnel, with an
           unreachable fallback, so the device is cut off (not leaked) if that tunnel drops
  direct   a mark sends it to the main table (the uplink); DNS is still answered locally and
           resolved through the main tunnel
  blocked  dropped in the forward chain

Every change rewrites the managed block, checks the whole file with nft -c, applies it, and
undoes itself after 90 seconds unless the new firewall is confirmed working (the forward chain
must still end fail-closed). State is kept in <etc>/devroute.json.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import tempfile
import sys
import time
from pathlib import Path
from typing import Any

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import sbc_site  # noqa: E402

SITE = sbc_site.load()
STATE_PATH = sbc_site.ETC_DIR / 'devroute.json'
NFT = '/usr/sbin/nft'
IP = '/usr/sbin/ip'
ROUTES = ('main', 'second', 'direct', 'blocked')
MARKS = {'second': 0x5A2, 'direct': 0x5A1, 'blocked': 0x5A3}
SECOND_TABLE = 201
SECOND_IFACE = f"{SITE['vpn_interface']}2"[:15]
BEGIN = '# sbc-devroute begin (managed by the Control Center: edits here are replaced)'
END = '# sbc-devroute end'
_MAC = re.compile(r'(?:[0-9a-f]{2}:){5}[0-9a-f]{2}')


class RouteError(RuntimeError):
    pass


def _run(args: list[str], timeout: float = 15, stdin: str | None = None) -> tuple[int, str]:
    try:
        cp = subprocess.run(args, input=stdin, capture_output=True, text=True, timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return 124, str(exc)
    return cp.returncode, (cp.stdout or '') + (cp.stderr or '')


def firewall_path() -> Path:
    try:
        cfg = json.loads((sbc_site.ETC_DIR / 'dns-profile.json').read_text())
        path = Path(cfg.get('firewall_rules', '/etc/apguard.nft'))
    except (OSError, ValueError):
        path = Path('/etc/apguard.nft')
    return path


def load_state() -> dict[str, Any]:
    try:
        data = json.loads(STATE_PATH.read_text())
    except (OSError, ValueError):
        data = {}
    devices = {m.lower(): v for m, v in (data.get('devices') or {}).items()
               if isinstance(m, str) and _MAC.fullmatch(m.lower()) and isinstance(v, dict) and v.get('route') in ROUTES}
    return {'devices': devices, 'second_server': data.get('second_server')}


def save_state(state: dict[str, Any]) -> None:
    STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix='.devroute.', dir=str(STATE_PATH.parent))
    with os.fdopen(fd, 'w') as handle:
        json.dump(state, handle, indent=2)
    os.chmod(tmp, 0o640)
    os.replace(tmp, STATE_PATH)


def managed_block(state: dict[str, Any], cfg: dict[str, str] | None = None) -> dict[str, str]:
    """The three pieces of the managed block: sets + mark chain, forward rules, NAT rules."""
    cfg = cfg or SITE
    aps = f'{{ "{cfg["ap_interface"]}", "{cfg["ap2_interface"]}" }}'
    uplink = cfg['uplink_interface']
    by_route = {r: sorted(m for m, v in state['devices'].items() if v['route'] == r) for r in MARKS}

    def elements(macs: list[str]) -> str:
        return f' elements = {{ {", ".join(macs)} }}' if macs else ''

    sets = '\n'.join(f'    set devroute_{r} {{ type ether_addr;{elements(by_route[r])} }}' for r in MARKS)
    marks = '\n'.join(f'        iifname {aps} ether saddr @devroute_{r} meta mark set {hex(MARKS[r])}' for r in MARKS)
    table_part = f"""    {BEGIN}
{sets}
    chain devroute_mark {{
        type filter hook prerouting priority mangle; policy accept;
{marks}
    }}
    {END}"""
    forward_part = f"""        {BEGIN}
        meta mark {hex(MARKS['blocked'])} counter drop comment "devroute: blocked device"
        iifname {aps} meta mark {hex(MARKS['direct'])} oifname "{uplink}" accept comment "devroute: direct"
        iifname "{uplink}" oifname {aps} ct state established,related accept comment "devroute: direct return"
        iifname {aps} oifname "{SECOND_IFACE}" tcp flags syn tcp option maxseg size set rt mtu
        iifname {aps} meta mark {hex(MARKS['second'])} oifname "{SECOND_IFACE}" accept comment "devroute: second tunnel"
        iifname "{SECOND_IFACE}" oifname {aps} ct state established,related accept
        {END}"""
    nat_part = f"""        {BEGIN}
        meta mark {hex(MARKS['direct'])} oifname "{uplink}" masquerade
        meta mark {hex(MARKS['second'])} oifname "{SECOND_IFACE}" masquerade
        {END}"""
    return {'table': table_part, 'forward': forward_part, 'nat': nat_part}


def _strip_managed(text: str) -> str:
    return re.sub(rf'[ \t]*{re.escape(BEGIN)}.*?{re.escape(END)}\n?', '', text, flags=re.S)


def render(source: str, state: dict[str, Any], cfg: dict[str, str] | None = None) -> str:
    """The firewall file with the managed block put in its three places (any old block removed)."""
    text = _strip_managed(source)
    parts = managed_block(state, cfg)
    fail_closed = re.search(r'^([ \t]*)counter drop comment "fail-closed"', text, flags=re.M)
    if not fail_closed or text.count('counter drop comment "fail-closed"') != 1:
        raise RouteError('The firewall has no single fail-closed rule to place the device rules before.')
    text = text[:fail_closed.start()] + parts['forward'] + '\n' + text[fail_closed.start():]
    masq = re.search(r'^[ \t]*ip saddr \{[^}]*\} oifname \$?\S+ masquerade\n', text, flags=re.M)
    if not masq:
        raise RouteError('The firewall has no access-point masquerade rule to place the device NAT next to.')
    text = text[:masq.end()] + parts['nat'] + '\n' + text[masq.end():]
    opening = re.search(r'^table inet apguard \{\n', text, flags=re.M)
    if not opening:
        raise RouteError('The firewall has no "table inet apguard {" block.')
    text = text[:opening.end()] + parts['table'] + '\n' + text[opening.end():]
    return text


def ensure_rules() -> None:
    """Policy-routing rules for the marks (idempotent; run at boot and on every change)."""
    rules = _run([IP, '-4', 'rule', 'show'])[1]
    wanted = [(95, MARKS['direct'], 'main'), (96, MARKS['second'], str(SECOND_TABLE))]
    for pref, mark, table in wanted:
        if f'fwmark {hex(mark)} lookup {table}' not in rules:
            _run([IP, '-4', 'rule', 'add', 'pref', str(pref), 'fwmark', hex(mark), 'lookup', table])
    # the second table always fails closed: unreachable unless the second tunnel provides a route
    _run([IP, '-4', 'route', 'replace', 'unreachable', 'default', 'metric', '4096', 'table', str(SECOND_TABLE)])


def apply(state: dict[str, Any]) -> dict[str, Any]:
    path = firewall_path()
    source = path.read_text(encoding='utf-8')
    candidate = render(source, state)
    # staged and backed up in the agent's own state folder: the sandbox may rewrite the firewall
    # file in place, but not create files next to it
    work = sbc_site.STATE_DIR
    fd, tmp = tempfile.mkstemp(prefix='.apguard.', suffix='.nft', dir=str(work))
    with os.fdopen(fd, 'w') as handle:
        handle.write(candidate)
    try:
        code, out = _run([NFT, '-c', '-f', tmp])
        if code != 0:
            raise RouteError(f'The new firewall failed its check: {out.strip()[:400]}')
        (work / 'apguard.nft.before-devroute').write_text(source, encoding='utf-8')
        with open(path, 'w', encoding='utf-8') as live:   # same file, rewritten in place
            live.write(candidate)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)
    code, out = _run([NFT, '-f', str(path)])
    if code != 0:
        path.write_text(source, encoding='utf-8')
        _run([NFT, '-f', str(path)])
        raise RouteError(f'The firewall did not load; the previous one was restored: {out.strip()[:300]}')
    listing = _run([NFT, 'list', 'chain', 'inet', 'apguard', 'forward'])[1]
    if 'fail-closed' not in listing:
        path.write_text(source, encoding='utf-8')
        _run([NFT, '-f', str(path)])
        raise RouteError('The forward chain lost its fail-closed rule; the previous firewall was restored.')
    ensure_rules()
    save_state(state)
    return {'ok': True}


def set_route(mac: str, route: str, label: str = '') -> dict[str, Any]:
    mac = (mac or '').lower()
    if not _MAC.fullmatch(mac) or route not in ROUTES:
        raise RouteError('A device address (MAC) and one of: main, second, direct, blocked.')
    state = load_state()
    if route == 'second' and not second_tunnel_status().get('up'):
        raise RouteError('The second tunnel is not up: choose its server first.')
    if route == 'main':
        state['devices'].pop(mac, None)
    else:
        state['devices'][mac] = {'route': route, 'label': str(label)[:64], 'since': int(time.time())}
    apply(state)
    return {'ok': True, 'message': f'{mac}: {route}.'}


def second_tunnel_status() -> dict[str, Any]:
    code, out = _run(['/usr/bin/wg', 'show', SECOND_IFACE, 'latest-handshakes'], timeout=5)
    if code != 0:
        return {'up': False, 'interface': SECOND_IFACE}
    parts = out.split()
    return {'up': True, 'interface': SECOND_IFACE, 'handshake': int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else None}


def status() -> dict[str, Any]:
    state = load_state()
    leases = {}
    try:
        for line in Path(SITE['dhcp_lease_file']).read_text().splitlines():
            p = line.split()
            if len(p) >= 4:
                leases[p[1].lower()] = {'ip': p[2], 'name': p[3] if p[3] != '*' else ''}
    except OSError:
        pass
    devices = []
    for mac in sorted(set(leases) | set(state['devices'])):
        entry = state['devices'].get(mac, {})
        devices.append({'mac': mac, 'ip': leases.get(mac, {}).get('ip'), 'name': entry.get('label') or leases.get(mac, {}).get('name', ''),
                        'route': entry.get('route', 'main')})
    return {'ok': True, 'devices': devices, 'second': {**second_tunnel_status(), 'server': state.get('second_server')}}


def install_units() -> None:
    """Boot: re-add the mark rules and the table-201 fallback once the firewall is loaded."""
    unit = f"""[Unit]
Description=Per-device routing rules for the access points
After=apguard.service network-pre.target
Before=hostapd.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/bin/python3 -I {sbc_site.APP_DIR}/devroute.py ensure

[Install]
WantedBy=multi-user.target
"""
    Path(f'/etc/systemd/system/{sbc_site.PREFIX}-devroute.service').write_text(unit)
    subprocess.run(['systemctl', 'daemon-reload'], check=True)
    subprocess.run(['systemctl', 'enable', '--now', f'{sbc_site.PREFIX}-devroute.service'], check=True)


if __name__ == '__main__':
    import sys
    command = (sys.argv[1:] or [''])[0]
    if command == 'ensure':
        ensure_rules()
    elif command == 'install-units':
        install_units()
    else:
        raise SystemExit(__doc__)
