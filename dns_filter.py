#!/usr/bin/env python3
"""Transactional AdGuard Home profile manager for the access-point networks."""
from __future__ import annotations

import ipaddress
import copy
import datetime as dt
import json
import os
import re
import shutil
import stat
import subprocess
import tempfile
from pathlib import Path
from typing import Any

import sbc_site

try:
    import yaml
except ImportError:  # pragma: no cover - exercised on minimal target installs
    yaml = None

AGH_BIN = Path('/opt/AdGuardHome/AdGuardHome')
AGH_CONFIG = Path('/etc/AdGuardHome/AdGuardHome.yaml')
AGH_WORK = Path('/var/lib/AdGuardHome')
DNSMASQ_CONFIG = Path('/etc/dnsmasq.d/ap.conf')
PROFILE_STATE = sbc_site.ETC_DIR / 'dns-profile.json'
DNS_CONFIG = sbc_site.ETC_DIR / 'dns-filter.json'
BACKUP_ROOT = sbc_site.BACKUP_DIR / 'dns'
ADGUARD_UNIT = 'adguardhome.service'

MANAGED_PREFIX = 'kickpi-managed-'
PROFILES: dict[str, dict[str, Any]] = {
    'standard': {
        'title': 'Standard',
        'description': 'Balanced advertising, tracker and threat filtering.',
        'filters': [
            (810001, 'HaGeZi Multi Normal', 'https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/multi.txt'),
            (810002, 'HaGeZi Threat Intelligence Feeds Mini', 'https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/tif.mini.txt'),
        ],
    },
    'aggressive': {
        'title': 'Aggressive',
        'description': 'Stronger privacy, advertising, telemetry, malware and scam filtering. Some legitimate domains may need allowlisting.',
        'filters': [
            (820001, 'HaGeZi Multi PRO++', 'https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/pro.plus.txt'),
            (820002, 'HaGeZi Threat Intelligence Feeds Mini', 'https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/tif.mini.txt'),
        ],
    },
    'tv': {
        'title': 'Smart TV privacy',
        'description': 'Aggressive threat filtering plus VIDAA-specific advertising, ACR and telemetry rules scoped only to the identified TV.',
        'filters': [
            (830001, 'HaGeZi Multi PRO++', 'https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/pro.plus.txt'),
            (830002, 'HaGeZi Threat Intelligence Feeds Mini', 'https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/tif.mini.txt'),
        ],
    }
}

_SITE = sbc_site.load()
# The access points come from the board's config.json; dns-filter.json may override them.
# The TV entries are empty until dns-filter.json names the TV (its address, MAC and, optionally,
# one cloud endpoint to drop); the Smart TV profile refuses to apply without them.
AP_DEFAULTS = {
    'ap2_ip': _SITE['ap2_ip'],
    'ap2_subnet': _SITE['ap2_subnet'],
    'ap2_interface': _SITE['ap2_interface'],
    'ap5_ip': _SITE['ap_ip'],
    'ap5_subnet': _SITE['ap_subnet'],
    'ap5_interface': _SITE['ap_interface'],
    'upstream': '100.64.0.23',
    'route_table': 200,
    'vidaa_ip': '',
    'vidaa_mac': '',
    'vidaa_interface': _SITE['ap2_interface'],
    'vidaa_endpoint_ip': '',
    'vidaa_endpoint_port': 0,
}


def tv_configured(config: dict[str, Any]) -> bool:
    return bool(config.get('vidaa_ip') and config.get('vidaa_mac'))

VIDAA_MANAGED_MARKER = '! KickPi managed VIDAA privacy rules'  # kept: it names rules already on devices
# Rules are scoped with AdGuard's $client modifier to the confirmed VIDAA
# lease only. Regional journal wildcards cover deployments outside Europe.
VIDAA_BLOCK_DOMAINS = (
    'api-logsdk.hismarttv.com', 'unified-ter.hismarttv.com', 'unified-exc.hismarttv.com',
    'api-cloudfalcon.hismarttv.com', 'api-gps-eu.hismarttv.com',
    'rpt-ads.vidaahub.com', 'rsc-ads.vidaahub.com', 'rpt-mntz.vidaahub.com',
    'rsc-mntz.vidaahub.com', 'rpt-mntz-azure.vidaahub.com',
    'monetization-ad-tracking.prod-eu-c.az.vidaahub.com',
    'monetization-tenant-ads.prod-eu-c.az.vidaahub.com', 'ads-privacy.vidaahub.com',
    'ad-cmp.hismarttv.com', 'ad-imp.hismarttv.com', 'ad-download.hismarttv.com',
    'ad-download-mam.hismarttv.com', 'ads-portal-cdn.vidaatv.net',
    'tracking-vss.vidaahub.com', 'abtest-tv.vidaahub.com', 'recommend-ui.vidaahub.com',
    'recommend-ui-eu.vidaahub.com', 'policy-jrnl-eu.vidaahub.com',
    'recommender-launcher.hismarttv.com', 'api-4know-eu.hismarttv.com',
    'api-shoppingguider.hismarttv.com', 'hisense-beacons.xumo.com',
    'hisense-lite-beacons.xumo.com', 'acr.unruly.co', 'trvdp.com',
    'log.core.cloud.vewd.com', 'metrics.core.cloud.vewd.com',
)
VIDAA_LEGACY_BLOCK_DOMAINS = (
    'exc-jrnl-af.vidaahub.com', 'exc-jrnl-na.vidaahub.com', 'exc-jrnl-eu.vidaahub.com', 'exc-jrnl-em.vidaahub.com',
    'ter-jrnl-af.vidaahub.com', 'ter-jrnl-na.vidaahub.com', 'ter-jrnl-eu.vidaahub.com', 'ter-jrnl-em.vidaahub.com',
    'policy-jrnl-af.vidaahub.com', 'policy-jrnl-na.vidaahub.com', 'policy-jrnl-eu.vidaahub.com', 'policy-jrnl-em.vidaahub.com',
    'crtv-mntz.vidaahub.com', 'dvcstatus-dataretrv.vidaahub.com', 'file-ul.vidaahub.com',
)
VIDAA_BLOCK_PATTERNS = (
    'recommend-ui-*.vidaahub.com', 'policy-jrnl-*.vidaahub.com',
    'ter-jrnl-*.vidaahub.com', 'exc-jrnl-*.vidaahub.com',
)
VIDAA_ALLOW_DOMAINS = (
    'api.us.hismarttv.com', 'api.euro.hismarttv.com', 'api.eu.hismarttv.com',
    'upgrade-eu.hismarttv.com', 'ota-tv.hismarttv.com',
    'partner.vidaahub.com', 'nrdp25.logs.netflix.com',
)
VIDAA_DHCP_COMMENT = '# KickPi managed: stable VIDAA TV DHCP lease'
VIDAA_FIREWALL_COMMENT = 'comment "kickpi-managed-vidaa-cloud-endpoint"'


def _vidaa_managed_rules(integration: dict[str, Any]) -> tuple[str, ...]:
    client = integration['vidaa_ip']
    return tuple(
        [VIDAA_MANAGED_MARKER]
        + [f'||{domain}^$client={client}' for domain in VIDAA_BLOCK_DOMAINS]
        + [f'||{pattern}^$client={client}' for pattern in VIDAA_BLOCK_PATTERNS]
        + [f'@@||{domain}^$client={client},important' for domain in VIDAA_ALLOW_DOMAINS]
    )


def _is_managed_vidaa_rule(rule: str) -> bool:
    if rule == VIDAA_MANAGED_MARKER:
        return True
    templates = tuple(f'||{domain}^$client=' for domain in (*VIDAA_BLOCK_DOMAINS, *VIDAA_BLOCK_PATTERNS, *VIDAA_LEGACY_BLOCK_DOMAINS))
    templates += tuple(f'@@||{domain}^$client=' for domain in VIDAA_ALLOW_DOMAINS)
    return rule.startswith(templates)


def _run(args: list[str], timeout: int = 20) -> tuple[int, str]:
    try:
        cp = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            text=True, timeout=timeout, check=False,
                            env={**os.environ, 'PATH': '/usr/sbin:/usr/bin:/sbin:/bin'})
        return cp.returncode, cp.stdout.strip()
    except (OSError, subprocess.TimeoutExpired) as exc:
        return 1, str(exc)


def _require_root() -> None:
    if os.geteuid() != 0:
        raise PermissionError(f'Run this operation with sudo: sudo {sbc_site.PREFIX}-admin dns profile PROFILE')


def _load_dns_config() -> dict[str, Any]:
    config = dict(AP_DEFAULTS)
    try:
        raw = json.loads(DNS_CONFIG.read_text(encoding='utf-8'))
        if isinstance(raw, dict):
            for key in (*AP_DEFAULTS.keys(), 'firewall_rules'):
                if key in raw:
                    config[key] = raw[key]
    except FileNotFoundError:
        pass
    except Exception as exc:
        raise RuntimeError(f'DNS integration settings are invalid: {exc}') from exc
    for key in ('ap2_ip', 'ap5_ip', 'upstream'):
        if not isinstance(config[key], str) or not re.fullmatch(r'[0-9.]{7,15}', config[key]):
            raise RuntimeError(f'Invalid DNS integration setting: {key}')
    for key in ('ap2_interface', 'ap5_interface', 'vidaa_interface'):
        if not isinstance(config[key], str) or not re.fullmatch(r'[A-Za-z0-9_.:-]{1,32}', config[key]):
            raise RuntimeError(f'Invalid DNS integration interface: {key}')
    for key in ('vidaa_ip', 'vidaa_endpoint_ip'):
        if config[key] == '':
            continue  # not configured
        try:
            ipaddress.ip_address(config[key])
        except (ValueError, TypeError):
            raise RuntimeError(f'Invalid DNS integration address: {key}')
    if config['vidaa_mac'] != '' and (not isinstance(config['vidaa_mac'], str) or not re.fullmatch(r'(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}', config['vidaa_mac'])):
        raise RuntimeError('Invalid VIDAA device MAC address.')
    if config['vidaa_endpoint_ip'] and (isinstance(config['vidaa_endpoint_port'], bool) or not isinstance(config['vidaa_endpoint_port'], int) or not 1 <= config['vidaa_endpoint_port'] <= 65535):
        raise RuntimeError('Invalid VIDAA endpoint port.')
    if not isinstance(config['route_table'], int) or not 1 <= config['route_table'] <= 2**31-1:
        raise RuntimeError('Invalid DNS routing table identifier.')
    return config


def available_profiles() -> list[dict[str, str]]:
    return [{'id': key, 'title': value['title'], 'description': value['description']}
            for key, value in PROFILES.items()]


def _load_yaml() -> dict[str, Any]:
    if yaml is None:
        raise RuntimeError('PyYAML is not installed. Install the Debian package python3-yaml.')
    if not AGH_CONFIG.is_file() or AGH_CONFIG.is_symlink():
        raise RuntimeError('AdGuard Home has not completed its first-run setup. Complete the wizard over the SSH tunnel first.')
    try:
        document = yaml.safe_load(AGH_CONFIG.read_text(encoding='utf-8'))
    except Exception as exc:
        raise RuntimeError(f'AdGuard Home configuration could not be parsed: {exc}') from exc
    if not isinstance(document, dict):
        raise RuntimeError('AdGuard Home configuration is not a YAML mapping.')
    users = document.get('users')
    if not isinstance(users, list) or not users:
        raise RuntimeError('Set an AdGuard Home administrator username and password in its first-run wizard before applying profiles.')
    return document


def _atomic_write(path: Path, data: bytes, mode: int = 0o640) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=f'.{path.name}.', dir=str(path.parent))
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temp_name, mode)
        os.replace(temp_name, path)
    finally:
        try:
            os.unlink(temp_name)
        except FileNotFoundError:
            pass


def _write_agh_config(data: bytes) -> None:
    _atomic_write(AGH_CONFIG, data, 0o640)
    try:
        import pwd, grp
        os.chown(AGH_CONFIG, pwd.getpwnam('adguardhome').pw_uid, grp.getgrnam('adguardhome').gr_gid)
    except (KeyError, PermissionError):
        raise RuntimeError('Could not set AdGuard Home configuration ownership to its dedicated service account.')


def _write_existing_regular_file(path: Path, data: bytes) -> None:
    """Safely replace bytes in one pre-existing allow-listed file without parent-dir write access.

    The root agent's systemd sandbox grants write access to the specific apguard
    rules file, not its whole parent directory. We therefore retain the inode and
    write through an O_NOFOLLOW descriptor. A failed write attempts an immediate
    restoration from the caller's already-created backup.
    """
    flags = os.O_RDWR | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_CLOEXEC', 0)
    fd = os.open(path, flags)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise RuntimeError(f'Refusing to write non-regular firewall source: {path}')
        if info.st_size > 1_048_576:
            raise RuntimeError(f'Refusing unexpectedly large firewall source ({info.st_size} bytes).')
        os.lseek(fd, 0, os.SEEK_SET)
        previous = os.read(fd, info.st_size)

        def replace_contents(payload: bytes) -> None:
            os.lseek(fd, 0, os.SEEK_SET)
            os.ftruncate(fd, 0)
            view = memoryview(payload)
            while view:
                written = os.write(fd, view)
                if written <= 0:
                    raise OSError('short write while updating firewall source')
                view = view[written:]
            os.fsync(fd)

        try:
            replace_contents(data)
        except Exception as write_error:
            try:
                replace_contents(previous)
            except Exception as restore_error:
                raise RuntimeError(f'Firewall source write failed and emergency restore also failed: {restore_error}') from write_error
            raise
    finally:
        os.close(fd)


def _get_firewall_path() -> Path:
    config = _load_dns_config()
    raw = config.get('firewall_rules')
    if not isinstance(raw, str) or not raw.startswith('/') or '\x00' in raw:
        raise RuntimeError('The apguard nftables source file has not been configured. Inspect `sudo systemctl cat apguard.service`, then rerun the installer with KICKPI_APGUARD_RULES=/absolute/path/to/rules.nft.')
    path = Path(raw)
    if path.is_symlink() or not path.is_file():
        raise RuntimeError(f'Configured apguard rules file is missing or unsafe: {path}')
    return path


def _make_agh_config(document: dict[str, Any], profile: str, integration: dict[str, Any]) -> dict[str, Any]:
    result = copy.deepcopy(document)
    dns = result.setdefault('dns', {})
    if not isinstance(dns, dict):
        raise RuntimeError('AdGuard Home dns configuration is not a mapping.')
    dns['bind_hosts'] = ['127.0.0.1', integration['ap2_ip'], integration['ap5_ip']]
    dns['port'] = 53
    dns['upstream_dns'] = [integration['upstream']]
    dns['bootstrap_dns'] = []
    dns['fallback_dns'] = []
    dns['allowed_clients'] = ['127.0.0.1', integration['ap2_subnet'], integration['ap5_subnet']]
    dns['disallowed_clients'] = []
    dns['ratelimit'] = 80
    dns['refuse_any'] = True
    dns['enable_dnssec'] = True
    dns['cache_enabled'] = True
    dns['cache_size'] = 16 * 1024 * 1024
    # AdGuard Home moved these settings out of `dns` into `filtering`
    # in v0.107.37. The current v1.0.0 schema retains that layout.
    filtering = result.setdefault('filtering', {})
    if not isinstance(filtering, dict):
        raise RuntimeError('AdGuard Home filtering configuration is not a mapping.')
    filtering['protection_enabled'] = True
    filtering['filtering_enabled'] = True
    filtering['blocking_mode'] = 'nxdomain'
    filtering['filters_update_interval'] = 24
    # Admin UI remains loopback-only. The portal is administered separately over HTTPS.
    http = result.setdefault('http', {})
    if isinstance(http, dict):
        http['address'] = '127.0.0.1:3000'
    # Replace only our own managed IDs. Preserve any operator-maintained lists.
    current = result.get('filters', [])
    if not isinstance(current, list):
        raise RuntimeError('AdGuard Home filter list is not a sequence.')
    preserved = [entry for entry in current if not (
        isinstance(entry, dict) and str(entry.get('name', '')).startswith(MANAGED_PREFIX)
    )]
    for filter_id, title, url in PROFILES[profile]['filters']:
        preserved.append({'enabled': True, 'url': url,
                          'name': MANAGED_PREFIX + title, 'id': filter_id})
    result['filters'] = preserved
    user_rules = filtering.setdefault('user_rules', [])
    if not isinstance(user_rules, list) or any(not isinstance(rule, str) for rule in user_rules):
        raise RuntimeError('AdGuard Home custom user_rules must be a list of text rules.')
    # Remove all previously managed VIDAA rules, even when its reserved IP changed.
    # Operator-maintained custom rules are preserved.
    user_rules = [rule for rule in user_rules if not _is_managed_vidaa_rule(rule)]
    if profile == 'tv':
        user_rules.extend(_vidaa_managed_rules(integration))
    filtering['user_rules'] = user_rules
    return result


def _patch_dnsmasq(source: str, integration: dict[str, Any], reserve_vidaa: bool = False) -> str:
    replacements = (
        (f"dhcp-option=tag:fenvi5,6,{integration['upstream']}", f"dhcp-option=tag:fenvi5,6,{integration['ap5_ip']}"),
        (f"dhcp-option=tag:fenvi2,6,{integration['upstream']}", f"dhcp-option=tag:fenvi2,6,{integration['ap2_ip']}"),
    )
    output = source
    for upstream_line, local_line in replacements:
        upstream_count = output.count(upstream_line)
        local_count = output.count(local_line)
        if upstream_count == 1 and local_count == 0:
            output = output.replace(upstream_line, local_line)
        elif upstream_count == 0 and local_count == 1:
            pass  # Already migrated to the corresponding local AdGuard listener.
        else:
            raise RuntimeError(f'Expected exactly one original or migrated dnsmasq directive for `{local_line}`; found original={upstream_count}, local={local_count}. No files were changed.')
    # Own only the exact reservation marker/host pair; refuse conflicting operator leases.
    managed_host = f"dhcp-host={integration['vidaa_mac']},{integration['vidaa_ip']},LivingRoomVIDAA,infinite"
    lines = [line for line in output.splitlines() if line.strip() not in (VIDAA_DHCP_COMMENT, managed_host)]
    mac = integration['vidaa_mac'].lower()
    ip = integration['vidaa_ip']
    for line in lines:
        stripped = line.strip()
        if not stripped.startswith('dhcp-host='):
            continue
        if mac in stripped.lower() and ip not in stripped:
            raise RuntimeError('An existing dnsmasq reservation for the VIDAA MAC uses a different IP. Resolve it manually before applying the TV profile.')
        if ip in stripped and mac not in stripped.lower():
            raise RuntimeError('The VIDAA reserved IP is already assigned to another dnsmasq host entry. Resolve the conflict manually.')
    output = '\n'.join(lines).rstrip() + '\n'
    if reserve_vidaa:
        output += VIDAA_DHCP_COMMENT + '\n' + managed_host + '\n'
    return output


def _patch_firewall(source: str, integration: dict[str, Any], profile: str = 'standard') -> str:
    old_udp = f'iifname {{ "{integration["ap2_interface"]}", "{integration["ap5_interface"]}" }} udp dport 53 dnat ip to {integration["upstream"]}'
    old_tcp = f'iifname {{ "{integration["ap2_interface"]}", "{integration["ap5_interface"]}" }} tcp dport 53 dnat ip to {integration["upstream"]}'
    local_udp = (f'iifname "{integration["ap2_interface"]}" udp dport 53 dnat ip to {integration["ap2_ip"]}',
                 f'iifname "{integration["ap5_interface"]}" udp dport 53 dnat ip to {integration["ap5_ip"]}')
    local_tcp = (f'iifname "{integration["ap2_interface"]}" tcp dport 53 dnat ip to {integration["ap2_ip"]}',
                 f'iifname "{integration["ap5_interface"]}" tcp dport 53 dnat ip to {integration["ap5_ip"]}')
    for original, local_rules in ((old_udp, local_udp), (old_tcp, local_tcp)):
        original_count = source.count(original)
        local_counts = tuple(source.count(rule) for rule in local_rules)
        if original_count == 1 and local_counts == (0, 0):
            source = source.replace(original, '\n'.join(local_rules))
        elif original_count == 0 and local_counts == (1, 1):
            pass  # Already redirected to local AdGuard listeners.
        else:
            raise RuntimeError(f'Expected the original or fully migrated AP DNS DNAT rules. Found original={original_count}, local={local_counts}; no firewall changes were made.')
    # Permit redirected client requests to the local DNS sockets before the AP catch-all drops.
    for iface, ip in ((integration['ap2_interface'], integration['ap2_ip']),
                      (integration['ap5_interface'], integration['ap5_ip'])):
        marker = f'iifname "{iface}" udp dport 67 accept'
        udp_rule = f'iifname "{iface}" ip daddr {ip} udp dport 53 accept'
        tcp_rule = f'iifname "{iface}" ip daddr {ip} tcp dport 53 accept'
        udp_count, tcp_count = source.count(udp_rule), source.count(tcp_rule)
        if (udp_count, tcp_count) == (0, 0):
            if source.count(marker) != 1:
                raise RuntimeError(f'Could not identify the single DHCP accept anchor for {iface}; no firewall changes were made.')
            additions = f'{marker}\n                {udp_rule}\n                {tcp_rule}'
            source = source.replace(marker, additions)
        elif (udp_count, tcp_count) != (1, 1):
            raise RuntimeError(f'Found an incomplete or duplicated AdGuard DNS input allow pair for {iface}; no firewall changes were made.')
    # Replace only the one rule owned by this module. Other operator rules survive.
    source = '\n'.join(line for line in source.splitlines() if VIDAA_FIREWALL_COMMENT not in line) + '\n'
    if profile == 'tv' and integration['vidaa_endpoint_ip']:
        anchor = 'ct state invalid drop'
        if source.count(anchor) != 1:
            raise RuntimeError('Could not identify the unique forward-chain invalid-state drop anchor for the VIDAA endpoint rule.')
        rule = (f'iifname "{integration["vidaa_interface"]}" ip saddr {integration["vidaa_ip"]} '
                f'ip daddr {integration["vidaa_endpoint_ip"]} tcp dport {integration["vidaa_endpoint_port"]} '
                f'counter drop {VIDAA_FIREWALL_COMMENT}')
        source = source.replace(anchor, anchor + '\n                ' + rule)
    return source


def _validate_agh_config(path: Path) -> None:
    code, output = _run([str(AGH_BIN), '--config', str(path), '--work-dir', str(AGH_WORK), '--check-config'], timeout=20)
    if code != 0:
        raise RuntimeError('AdGuard Home rejected the proposed configuration: ' + output[:1200])


def _validate_firewall_text(reference: Path, content: str) -> None:
    fd, temp_name = tempfile.mkstemp(prefix='kickpi-dns-check-', suffix='.nft', dir='/tmp')
    temp_path = Path(temp_name)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temp_path, 0o600)
        code, output = _run(['/usr/sbin/nft', '-c', '-f', str(temp_path)], timeout=15)
        if code != 0:
            raise RuntimeError('The proposed AP firewall rules failed nft syntax validation: ' + output[:1000])
    finally:
        temp_path.unlink(missing_ok=True)


def status() -> dict[str, Any]:
    integration = _load_dns_config()
    active_rc, active_output = _run(['/usr/bin/systemctl', 'is-active', ADGUARD_UNIT], timeout=5)
    current = 'not configured'
    try:
        state = json.loads(PROFILE_STATE.read_text(encoding='utf-8'))
        current = str(state.get('profile', current))
    except Exception:
        pass
    details = {
        'installed': AGH_BIN.is_file(),
        'config_ready': AGH_CONFIG.is_file(),
        'running': active_rc == 0 and active_output == 'active',
        'service_state': active_output or 'unknown',
        'profile': current,
        'dns_listeners': [integration['ap2_ip'], integration['ap5_ip']],
        'upstream': integration['upstream'],
        'firewall_rules_file_configured': bool(integration.get('firewall_rules')),
        'profiles': available_profiles(),
    }
    return {'ok': True, 'dns': details}


def validate() -> dict[str, Any]:
    integration = _load_dns_config()
    if not AGH_BIN.is_file() or not AGH_CONFIG.is_file():
        raise RuntimeError('AdGuard Home binary/configuration is not installed and initialized yet.')
    doc = _load_yaml()
    candidate = _make_agh_config(doc, 'standard', integration)
    tv_candidate = _make_agh_config(doc, 'tv', integration)
    with tempfile.NamedTemporaryFile('w', encoding='utf-8', suffix='.yaml', delete=False) as handle:
        temp_path = Path(handle.name)
        yaml.safe_dump(candidate, handle, sort_keys=False)
    try:
        _validate_agh_config(temp_path)
    finally:
        temp_path.unlink(missing_ok=True)
    with tempfile.NamedTemporaryFile('w', encoding='utf-8', suffix='.yaml', delete=False) as handle:
        tv_temp_path = Path(handle.name)
        yaml.safe_dump(tv_candidate, handle, sort_keys=False)
    try:
        _validate_agh_config(tv_temp_path)
    finally:
        tv_temp_path.unlink(missing_ok=True)
    firewall = _get_firewall_path()
    dnsmasq_text = DNSMASQ_CONFIG.read_text(encoding='utf-8')
    _patch_dnsmasq(dnsmasq_text, integration)
    if tv_configured(integration):
        _patch_dnsmasq(dnsmasq_text, integration, reserve_vidaa=True)
    firewall_text = firewall.read_text(encoding='utf-8')
    proposed_firewall = _patch_firewall(firewall_text, integration)
    _validate_firewall_text(firewall, proposed_firewall)
    proposed_tv_firewall = _patch_firewall(firewall_text, integration, 'tv')
    _validate_firewall_text(firewall, proposed_tv_firewall)
    return {'ok': True, 'message': 'AdGuard configuration, DNS DHCP directives and proposed AP firewall rules passed preflight. No live settings were changed.'}


def _ensure_uid_route() -> None:
    integration = _load_dns_config()
    try:
        import pwd
        uid = pwd.getpwnam('adguardhome').pw_uid
    except KeyError as exc:
        raise RuntimeError('The dedicated adguardhome account is missing. Run the network-filtering installer first.') from exc
    # The policy table already carries default dev <vpn> plus an unreachable fallback.
    vpn_dev = f"dev {_SITE['vpn_interface']}"
    route = _run(['/usr/sbin/ip', '-4', 'route', 'show', 'table', str(integration['route_table'])])[1]
    if vpn_dev not in route or 'unreachable default' not in route:
        raise RuntimeError('VPN policy table is missing its VPN and unreachable fallback routes. Refusing to route AdGuard upstream traffic.')
    rules = _run(['/usr/sbin/ip', '-4', 'rule', 'show'])[1]
    # DNS replies to local AP clients must use the connected AP interface.
    # Without these destination rules, source-based AP policy routing can send
    # locally generated replies into the VPN tunnel instead of back to Wi-Fi.
    for subnet in (integration['ap2_subnet'], integration['ap5_subnet']):
        expected = f'to {subnet} lookup main'
        if expected not in rules:
            code, output = _run(['/usr/sbin/ip', '-4', 'rule', 'add', 'priority', '80', 'to', subnet, 'lookup', 'main'])
            if code != 0:
                raise RuntimeError(f'Could not install the local return route for {subnet}: {output}')
            rules = _run(['/usr/sbin/ip', '-4', 'rule', 'show'])[1]
    rule = f'uidrange {uid}-{uid} lookup {integration["route_table"]}'
    if rule not in rules:
        code, output = _run(['/usr/sbin/ip', '-4', 'rule', 'add', 'priority', '90', 'uidrange', f'{uid}-{uid}', 'lookup', str(integration['route_table'])])
        if code != 0:
            raise RuntimeError('Could not install AdGuard UID-based VPN routing rule: ' + output)
    probe_rc, probe = _run(['/usr/sbin/ip', '-4', 'route', 'get', integration['upstream'], 'uid', str(uid)], timeout=5)
    if probe_rc != 0 or vpn_dev not in probe:
        raise RuntimeError('AdGuard upstream routing preflight did not select the VPN. DNS profile was not applied: ' + probe)
    probes = ((str(ipaddress.ip_network(integration['ap2_subnet'])[10]), integration['ap2_interface']),
              (str(ipaddress.ip_network(integration['ap5_subnet'])[10]), integration['ap5_interface']))
    for address, interface in probes:
        return_rc, return_route = _run(['/usr/sbin/ip', '-4', 'route', 'get', address, 'uid', str(uid)], timeout=5)
        if return_rc != 0 or f'dev {interface}' not in return_route:
            raise RuntimeError(f'AdGuard DNS reply routing to {address} does not use {interface}: {return_route}')


def apply_profile(profile: str) -> dict[str, Any]:
    _require_root()
    if profile not in PROFILES:
        raise ValueError('Unknown DNS profile. Choose: ' + ', '.join(PROFILES))
    if yaml is None:
        raise RuntimeError('PyYAML is required. Install python3-yaml first.')
    if not AGH_BIN.is_file() or not AGH_CONFIG.is_file():
        raise RuntimeError('Install AdGuard Home and complete its first-run setup over SSH before applying a DNS profile.')
    if _run(['/usr/bin/systemctl', 'is-active', '--quiet', ADGUARD_UNIT], timeout=5)[0] != 0:
        raise RuntimeError('AdGuard Home is not running. Start adguardhome.service and complete its setup first.')
    integration = _load_dns_config()
    if profile == 'tv' and not tv_configured(integration):
        raise RuntimeError('The Smart TV profile needs the TV: set vidaa_ip and vidaa_mac in dns-filter.json first.')
    firewall_path = _get_firewall_path()
    original_yaml = AGH_CONFIG.read_bytes()
    original_dnsmasq = DNSMASQ_CONFIG.read_bytes()
    original_firewall = firewall_path.read_bytes()
    document = yaml.safe_load(original_yaml.decode('utf-8'))
    if not isinstance(document, dict):
        raise RuntimeError('AdGuard Home configuration is not a YAML mapping.')
    candidate = _make_agh_config(document, profile, integration)
    yaml_text = yaml.safe_dump(candidate, sort_keys=False, allow_unicode=True)
    # Validate all three edits before replacing any live file.
    with tempfile.NamedTemporaryFile('w', encoding='utf-8', suffix='.yaml', delete=False) as handle:
        test_yaml = Path(handle.name)
        handle.write(yaml_text)
    try:
        _validate_agh_config(test_yaml)
    finally:
        test_yaml.unlink(missing_ok=True)
    dnsmasq_text = _patch_dnsmasq(original_dnsmasq.decode('utf-8'), integration, reserve_vidaa=profile == 'tv')
    firewall_text = _patch_firewall(original_firewall.decode('utf-8'), integration, profile)
    _validate_firewall_text(firewall_path, firewall_text)
    _ensure_uid_route()

    stamp = dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    backup = BACKUP_ROOT / stamp
    backup.mkdir(parents=True, mode=0o700, exist_ok=False)
    for path, content in ((AGH_CONFIG, original_yaml), (DNSMASQ_CONFIG, original_dnsmasq), (firewall_path, original_firewall)):
        dest = backup / path.name
        dest.write_bytes(content)
        os.chmod(dest, 0o600)
    metadata = {'timestamp': stamp, 'profile': profile, 'firewall_rules': str(firewall_path)}
    if PROFILE_STATE.is_file() and not PROFILE_STATE.is_symlink():
        shutil.copyfile(PROFILE_STATE, backup / 'previous-profile.json')
        os.chmod(backup / 'previous-profile.json', 0o600)
    (backup / 'manifest.json').write_text(json.dumps(metadata, indent=2) + '\n', encoding='utf-8')
    os.chmod(backup / 'manifest.json', 0o600)

    try:
        _atomic_write(DNSMASQ_CONFIG, dnsmasq_text.encode('utf-8'), 0o640)
        _write_existing_regular_file(firewall_path, firewall_text.encode('utf-8'))
        _write_agh_config(yaml_text.encode('utf-8'))
        code, output = _run(['/usr/bin/systemctl', 'restart', ADGUARD_UNIT], timeout=30)
        if code != 0:
            raise RuntimeError('AdGuard Home restart failed: ' + output[:600])
        code, output = _run(['/usr/bin/systemctl', 'is-active', '--quiet', ADGUARD_UNIT], timeout=8)
        if code != 0:
            raise RuntimeError('AdGuard Home did not remain active after the profile change.')
        code, output = _run(['/usr/bin/systemctl', 'restart', 'dnsmasq.service'], timeout=25)
        if code != 0:
            raise RuntimeError('dnsmasq failed to restart: ' + output[:600])
        code, output = _run(['/usr/bin/systemctl', 'restart', 'apguard.service'], timeout=25)
        if code != 0:
            raise RuntimeError('apguard failed to restart: ' + output[:600])
        (PROFILE_STATE.parent).mkdir(parents=True, exist_ok=True)
        _atomic_write(PROFILE_STATE, (json.dumps(metadata, indent=2) + '\n').encode(), 0o640)
        return {'ok': True, 'message': f'{PROFILES[profile]["title"]} DNS filtering profile applied.', 'profile': profile, 'backup': str(backup)}
    except Exception as exc:
        _write_agh_config(original_yaml)
        _atomic_write(DNSMASQ_CONFIG, original_dnsmasq, 0o640)
        _write_existing_regular_file(firewall_path, original_firewall)
        _run(['/usr/bin/systemctl', 'restart', ADGUARD_UNIT], timeout=25)
        _run(['/usr/bin/systemctl', 'restart', 'dnsmasq.service'], timeout=25)
        _run(['/usr/bin/systemctl', 'restart', 'apguard.service'], timeout=25)
        raise RuntimeError(f'Profile application failed and the three configuration files were rolled back: {exc}') from exc


def rollback() -> dict[str, Any]:
    _require_root()
    if not BACKUP_ROOT.is_dir():
        raise RuntimeError('No DNS profile backups are available.')
    backups = sorted((p for p in BACKUP_ROOT.iterdir() if p.is_dir() and (p / 'manifest.json').is_file()), reverse=True)
    if not backups:
        raise RuntimeError('No complete DNS profile backup was found.')
    backup = backups[0]
    manifest = json.loads((backup / 'manifest.json').read_text(encoding='utf-8'))
    firewall = Path(manifest.get('firewall_rules', ''))
    mapping = [(AGH_CONFIG, backup / AGH_CONFIG.name),
               (DNSMASQ_CONFIG, backup / DNSMASQ_CONFIG.name),
               (firewall, backup / firewall.name)]
    if not all(src.is_file() and not src.is_symlink() for _, src in mapping):
        raise RuntimeError('The most recent DNS backup is incomplete; refusing partial rollback.')
    for dest, src in mapping:
        if dest == AGH_CONFIG:
            _write_agh_config(src.read_bytes())
        else:
            _atomic_write(dest, src.read_bytes(), 0o640) if dest != firewall else _write_existing_regular_file(dest, src.read_bytes())
    for unit in (ADGUARD_UNIT, 'dnsmasq.service', 'apguard.service'):
        code, output = _run(['/usr/bin/systemctl', 'restart', unit], timeout=25)
        if code != 0:
            raise RuntimeError(f'Rollback restored files but {unit} failed to restart: {output[:600]}')
    previous_state = backup / 'previous-profile.json'
    if previous_state.is_file() and not previous_state.is_symlink():
        _atomic_write(PROFILE_STATE, previous_state.read_bytes(), 0o640)
    else:
        PROFILE_STATE.unlink(missing_ok=True)
    return {'ok': True, 'message': f'Last DNS profile backup restored from {backup}.'}
