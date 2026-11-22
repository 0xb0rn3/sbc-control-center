"""What this installation calls itself, where it keeps its files, and the board's own settings.

One codebase runs on every board. The names below come from the environment the systemd units
set, so a fresh install uses the generic sbc-control-center names and an older install keeps its
own without moving a single file. Without the variables the name is the /opt/<name> directory
the code is installed in, and the prefix is its first word:

  SBC_NAME          application directories and the agent/web unit names   (sbc-control-center)
  SBC_PREFIX        the helper units: <prefix>-dns-bypass, <prefix>-p0f@...  (sbc)
  SBC_PORTAL_USER   the unprivileged account the web portal runs as        (SBC_NAME)
  SBC_PORTAL_GROUP  its group, the only one the agent socket accepts       (SBC_NAME)

The board's own settings (its label, interfaces, SSIDs, subnets, VPN unit) live in
<etc>/config.json on the device, never in the code, so the public repository carries no
personal names or hardware identifiers. Everything read from the file is validated here.
"""
from __future__ import annotations

import grp
import ipaddress
import json
import os
import pwd
import re
from pathlib import Path
from typing import Any

_UNIT_WORD = re.compile(r'[a-z][a-z0-9-]{0,31}')


def _word(var: str, default: str) -> str:
    value = os.environ.get(var, '')
    return value if _UNIT_WORD.fullmatch(value) else default


def _installed_name() -> str:
    """/opt/<name>/sbc_site.py names the installation; a source tree gets the generic name."""
    here = Path(__file__).resolve().parent
    return here.name if here.parent == Path('/opt') and _UNIT_WORD.fullmatch(here.name) else 'sbc-control-center'


def _account(var: str, candidates: list[str]) -> str:
    value = os.environ.get(var, '')
    if _UNIT_WORD.fullmatch(value):
        return value
    for name in candidates:
        try:
            pwd.getpwnam(name) if var.endswith('USER') else grp.getgrnam(name)
            return name
        except KeyError:
            continue
    return candidates[-1]


NAME = _word('SBC_NAME', _installed_name())
PREFIX = _word('SBC_PREFIX', NAME.split('-', 1)[0])
# older installs run the portal as <prefix>-portal; fresh ones as <name>
PORTAL_USER = _account('SBC_PORTAL_USER', [f'{PREFIX}-portal', NAME])
PORTAL_GROUP = _account('SBC_PORTAL_GROUP', [f'{PREFIX}-portal', NAME])

APP_DIR = Path('/opt') / NAME
ETC_DIR = Path('/etc') / NAME
STATE_DIR = Path('/var/lib') / NAME
WEB_STATE_DIR = Path('/var/lib') / f'{NAME}-web'
RUN_DIR = Path('/run') / NAME
BACKUP_DIR = Path('/var/backups') / NAME
SOCKET_PATH = RUN_DIR / 'agent.sock'
CONFIG_PATH = ETC_DIR / 'config.json'

AGENT_UNIT = f'{NAME}-agent'
WEB_UNIT = f'{NAME}-web'
DNS_BYPASS_UNIT = f'{PREFIX}-dns-bypass'
DNS_BYPASS_STATE = Path('/var/lib') / f'{PREFIX}-dns-bypass'
WIFI_WATCHDOG_UNIT = f'{PREFIX}-wifi-watchdog'
P0F_UNIT = f'{PREFIX}-p0f'            # template: <unit>@<interface>
ARPWATCH_UNIT = f'{PREFIX}-arpwatch'  # template: <unit>@<interface>
P0F_LOG_DIR = Path('/var/log') / f'{PREFIX}-p0f'
USER_AGENT = 'SBCControlCenter'

DEFAULTS: dict[str, str] = {
    'device_label': 'SBC Control Center',
    'home_location': '',            # "lat,lon" for the threat map (empty: the time zone's city)
    'greeting_name': '',            # living-room greeting: "Good evening, <name>" (empty: no name)
    'uplink_interface': 'end0',
    'ap_interface': 'wlan1',
    'ap_label': '5 GHz access point',
    'ap_ssid': 'SBC-5G',
    'ap_ip': '192.168.50.1',
    'ap_subnet': '192.168.50.0/24',
    'ap2_interface': 'wlan0',
    'ap2_label': '2.4 GHz access point',
    'ap2_ssid': 'SBC-2G',
    'ap2_ip': '192.168.60.1',
    'ap2_subnet': '192.168.60.0/24',
    'vpn_interface': 'wg0',
    'vpn_label': 'VPN tunnel',
    'vpn_unit': 'wg-quick@wg0',
    'dhcp_lease_file': '/var/lib/misc/dnsmasq.leases',
}

_IFACE = re.compile(r'[A-Za-z0-9_.:-]{1,32}')
_LABEL = re.compile(r'[^\x00-\x1f\x7f<>]{1,64}')


def _valid(key: str, value: str) -> bool:
    if key.endswith('_interface'):
        return bool(_IFACE.fullmatch(value))
    if key == 'vpn_unit':
        return bool(re.fullmatch(r'wg-quick@[A-Za-z0-9_.-]{1,32}', value))
    if key.endswith('_ip'):
        try:
            return ipaddress.ip_address(value).version == 4
        except ValueError:
            return False
    if key.endswith('_subnet'):
        try:
            return ipaddress.ip_network(value, strict=True).version == 4
        except ValueError:
            return False
    if key.endswith('_ssid'):
        return 0 < len(value.encode('utf-8')) <= 32 and '\n' not in value
    if key == 'dhcp_lease_file':
        return value.startswith('/') and '..' not in value and len(value) < 200
    return bool(_LABEL.fullmatch(value))


def load(path: Path | None = None) -> dict[str, str]:
    """The board's settings: config.json over the generic defaults, invalid values ignored."""
    cfg = dict(DEFAULTS)
    try:
        loaded: Any = json.loads((path or CONFIG_PATH).read_text())
    except Exception:
        loaded = {}
    if isinstance(loaded, dict):
        for key in DEFAULTS:
            value = loaded.get(key)
            if isinstance(value, str) and _valid(key, value):
                cfg[key] = value
    return cfg


def ap_interfaces(cfg: dict[str, str]) -> list[str]:
    return [cfg['ap_interface'], cfg['ap2_interface']]


def ap_subnets(cfg: dict[str, str]) -> list[str]:
    return [cfg['ap_subnet'], cfg['ap2_subnet']]


def public_view(cfg: dict[str, str]) -> dict[str, str]:
    """What the signed-in browser may see: everything here is already visible on the device."""
    return {k: cfg[k] for k in DEFAULTS if k != 'dhcp_lease_file'}
