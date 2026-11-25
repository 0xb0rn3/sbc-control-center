"""Read-only ZLT X17U radio status adapter.

The X17U's documented local RPC is used only for pre-login, login and the
read-only network-info command. No configuration, SIM, SMS, reboot or write
RPCs are implemented here. Configure credentials in /etc/<app>/router.json.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import secrets
import stat
import threading
import time
import urllib.request
from pathlib import Path
from typing import Any

import sbc_site

# Firmware endpoint IDs also used by the published Airtel ODU App's ZLT client.
CMD_LOGIN_TOKEN = "3830c61a-620d-47da-ae47-33d8401401c4"
CMD_LOGIN = "d2aa9843-494b-4947-9621-a46ec652ecd9"
CMD_PRELOGIN = "835e31b3-a45a-4504-80df-586bf8a509aa"
CMD_NETINFO = "89af35c9-b448-4fc7-a477-828a3e9467f8"

CONFIG_PATH = sbc_site.ETC_DIR / "router.json"
_CACHE_SECONDS = 45
_cache_lock = threading.Lock()
_cache: tuple[float, dict[str, Any]] | None = None
_router_lock = threading.Lock()


class RouterUnavailable(RuntimeError):
    pass


def _config() -> dict[str, str]:
    try:
        info = CONFIG_PATH.stat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or (stat.S_IMODE(info.st_mode) & 0o027):
            raise RouterUnavailable("Router configuration must be a root-owned 0640 file.")
        loaded = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise RouterUnavailable("Router credentials are not configured.")
    except RouterUnavailable:
        raise
    except Exception:
        raise RouterUnavailable("Router configuration could not be read.")
    if not isinstance(loaded, dict):
        raise RouterUnavailable("Router configuration is invalid.")
    host = loaded.get("host", "192.168.1.1")
    username, password = loaded.get("username"), loaded.get("password")
    if not isinstance(host, str) or not isinstance(username, str) or not isinstance(password, str):
        raise RouterUnavailable("Router host, username and password are required.")
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        raise RouterUnavailable("Router host must be a private IPv4 address.")
    if address.version != 4 or not address.is_private or address.is_loopback or address.is_link_local:
        raise RouterUnavailable("Router host must be a private LAN IPv4 address.")
    if not username or len(username) > 64 or not password or len(password) > 256:
        raise RouterUnavailable("Router username or password is invalid.")
    return {"host": str(address), "username": username, "password": password}


def _rpc(host: str, command: str, session_id: str = "", method: str = "GET",
         params: dict[str, Any] | None = None, timeout: float = 4.0) -> dict[str, Any]:
    payload = dict(params or {})
    payload.update({"cmd": command, "method": method, "sessionId": session_id})
    body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    request = urllib.request.Request(
        f"http://{host}/cgi-bin/http.cgi",
        data=body,
        headers={
            "Content-Type": "application/json;charset=UTF-8",
            "Referer": f"http://{host}/index.html",
            "Accept": "application/json",
        },
        method="POST",
    )
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(request, timeout=timeout) as response:
        raw = response.read(128 * 1024).decode("utf-8", "replace")
    start = raw.find("{")
    if start < 0:
        raise RouterUnavailable("The router returned an unreadable status response.")
    try:
        parsed = json.loads(raw[start:])
    except json.JSONDecodeError:
        raise RouterUnavailable("The router returned invalid status data.")
    if not isinstance(parsed, dict):
        raise RouterUnavailable("The router returned an invalid status object.")
    return parsed


def _read_network_info(cfg: dict[str, str]) -> dict[str, Any]:
    host, username, password = cfg["host"], cfg["username"], cfg["password"]
    # The firmware allows one admin session per account; serialize login and read.
    with _router_lock:
        try:
            try:
                _rpc(host, CMD_PRELOGIN, timeout=2.0)
            except Exception:
                pass
            token_result = _rpc(host, CMD_LOGIN_TOKEN)
            token = token_result.get("token")
            if not token_result.get("success") or not isinstance(token, str) or not token:
                raise RouterUnavailable("The router did not issue a login token.")
            session_id = secrets.token_hex(32)
            login = _rpc(host, CMD_LOGIN, session_id, "POST", {
                "username": username,
                "passwd": hashlib.sha256((token + password).encode("utf-8")).hexdigest(),
                "token": token,
            })
            if not login.get("success"):
                message = str(login.get("message", ""))
                if message == "alreadyLogin":
                    raise RouterUnavailable("The router admin account is already signed in elsewhere.")
                raise RouterUnavailable("The router rejected the configured credentials.")
            session_id = str(login.get("sessionId") or session_id)
            info = _rpc(host, CMD_NETINFO, session_id)
            if not info.get("success"):
                raise RouterUnavailable("The router did not return radio status.")
            # Return only fields needed for cell identity, signal display and
            # coarse fallback. Subscriber identifiers are deliberately omitted.
            allowed = (
                "ECGI", "ecgi", "CELL_ID", "cell_id", "MCC", "MNC", "PCI",
                "network_operator", "network_type_str", "currentband", "FREQ",
                "RSRP", "RSRQ", "SINR", "RSSI", "wan_ip",
            )
            safe = {key: info[key] for key in allowed if key in info}
            safe["router_host"] = host
            return safe
        except RouterUnavailable:
            raise
        except Exception as exc:
            raise RouterUnavailable(f"Router status could not be read ({type(exc).__name__}).")


def network_info() -> dict[str, Any]:
    global _cache
    now = time.time()
    with _cache_lock:
        if _cache and now - _cache[0] < _CACHE_SECONDS:
            return dict(_cache[1])
    cfg = _config()
    result = _read_network_info(cfg)
    with _cache_lock:
        _cache = (now, dict(result))
    return result
