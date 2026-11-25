"""Best-effort cell-tower geolocation for the SBC Control Center.

This module deliberately does not use the SBC's public IP: when the SBC is a VPN
server, that address can identify the VPN exit rather than the router's location.
Call resolve_cell() with read-only radio fields obtained from the local ZLT router.
"""
from __future__ import annotations

import json
import re
import threading
import time
import urllib.parse
import urllib.request
from typing import Any

API_URL = "https://mcc-mnc.org/api/v1/cells"
API_ATTRIBUTION = "Cell data from OpenCelliD (https://opencellid.org), licensed CC BY-SA 4.0."
_CACHE_TTL = 6 * 60 * 60
_cache: dict[tuple[str, str, str, str], tuple[float, dict[str, Any]]] = {}
_cache_lock = threading.Lock()


def _digits(value: Any, name: str, width: int) -> str:
    text = str(value).strip()
    if not text.isdigit() or len(text) > width:
        raise ValueError(f"Invalid {name}")
    return text


def _cell_number(value: Any) -> int:
    """Accept decimal ECI or hexadecimal ECI (optionally prefixed by 0x)."""
    text = str(value).strip()
    if not text:
        raise ValueError("Missing LTE cell identity")
    if text.lower().startswith("0x"):
        number = int(text, 16)
    elif re.fullmatch(r"[0-9a-fA-F]{1,7}", text) and re.search(r"[a-fA-F]", text):
        number = int(text, 16)
    elif text.isdigit():
        # Router CELL_ID values are commonly hex without a 0x prefix.
        number = int(text, 10)
    else:
        raise ValueError("Invalid LTE cell identity")
    if not 0 <= number < (1 << 28):
        raise ValueError("LTE ECI must be a 28-bit value")
    return number


def observation_from_router(info: dict[str, Any]) -> dict[str, str]:
    """Normalize fields from the ZLT X17U status response.

    Supports either separate MCC/MNC/CELL_ID fields, or the composite ECGI
    format shown by the X17U (e.g. 6400503CE233). PCI is intentionally ignored:
    PCI is reused by many cells and is not a globally unique cell identity.
    """
    if not isinstance(info, dict):
        raise ValueError("Router information must be an object")

    mcc = info.get("MCC")
    mnc = info.get("MNC")
    cell = info.get("CELL_ID") or info.get("cell_id") or info.get("ECI")
    ecgi = info.get("ECGI") or info.get("ecgi")

    if ecgi and not cell:
        value = re.sub(r"[^0-9a-fA-F]", "", str(ecgi))
        if len(value) < 6:
            raise ValueError("ECGI is incomplete")
        # ECGI is PLMN (MCC + MNC) followed by the 28-bit LTE ECI.
        mcc, mnc, cell = value[:3], value[3:5], value[5:]

    if not (mcc and mnc and cell):
        raise ValueError("Router must provide MCC, MNC and LTE CELL_ID/ECGI")

    # X17U's CELL_ID is reported as hex. Preserve that interpretation for
    # alphabetic values; numeric-only values are treated as decimal.
    return {
        "mcc": _digits(mcc, "MCC", 3),
        "mnc": _digits(mnc, "MNC", 3),
        "cell": str(_cell_number(cell)),
        "radio": "LTE",
    }


def _request_json(url: str, timeout: float = 6.0) -> dict[str, Any]:
    request = urllib.request.Request(
        url,
        headers={"Accept": "application/json", "User-Agent": "SBC-Control-Center/1.0"},
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        if response.status != 200:
            raise OSError(f"Cell lookup returned HTTP {response.status}")
        raw = response.read(256 * 1024)
    payload = json.loads(raw.decode("utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("Unexpected cell lookup response")
    return payload


def lookup_cell(observation: dict[str, str], fetch_json=_request_json) -> dict[str, Any]:
    """Look up an LTE cell; return candidates without guessing between duplicates."""
    mcc = _digits(observation.get("mcc"), "MCC", 3)
    mnc = _digits(observation.get("mnc"), "MNC", 3)
    cell = str(_cell_number(observation.get("cell")))
    radio = str(observation.get("radio", "LTE")).upper()
    if radio != "LTE":
        raise ValueError("Only LTE ECI lookup is supported by this resolver")

    key = (mcc, mnc, cell, radio)
    now = time.time()
    with _cache_lock:
        cached = _cache.get(key)
        if cached and now - cached[0] < _CACHE_TTL:
            return dict(cached[1])

    query = urllib.parse.urlencode({"mcc": mcc, "mnc": mnc, "cell": cell, "radio": radio})
    payload = fetch_json(f"{API_URL}?{query}")
    rows = payload.get("data", [])
    if not isinstance(rows, list):
        raise ValueError("Cell lookup data was not a list")

    candidates = []
    for row in rows[:50]:
        if not isinstance(row, dict):
            continue
        try:
            lat, lon = float(row["lat"]), float(row["lon"])
        except (KeyError, TypeError, ValueError):
            continue
        if not (-90 <= lat <= 90 and -180 <= lon <= 180):
            continue
        candidates.append({
            "latitude": lat,
            "longitude": lon,
            "range_m": row.get("range"),
            "samples": row.get("samples"),
            "area": row.get("area"),
            "last_seen": row.get("lastSeen"),
            "radio": row.get("radio", radio),
        })

    if not candidates:
        result = {
            "status": "not_found",
            "source": "OpenCelliD via mcc-mnc.org",
            "message": "No measured location is available for this cell. This does not mean the cell does not exist.",
            "candidates": [],
            "attribution": API_ATTRIBUTION,
        }
    elif len(candidates) == 1:
        result = {
            "status": "estimated",
            "source": "OpenCelliD via mcc-mnc.org",
            "message": "Estimated serving-cell area, not the handset's exact position.",
            "location": candidates[0],
            "candidates": candidates,
            "attribution": API_ATTRIBUTION,
        }
    else:
        result = {
            "status": "ambiguous",
            "source": "OpenCelliD via mcc-mnc.org",
            "message": "This ECI has multiple records because the router did not expose TAC. No candidate was selected.",
            "candidates": candidates,
            "attribution": API_ATTRIBUTION,
        }

    with _cache_lock:
        _cache[key] = (now, result)
    return dict(result)


def resolve_from_router(info: dict[str, Any], fetch_json=_request_json) -> dict[str, Any]:
    """Public entry point for a caller that already read the router's status fields."""
    try:
        observation = observation_from_router(info)
    except (TypeError, ValueError) as exc:
        return {
            "status": "unavailable",
            "source": "ZLT router radio status",
            "message": str(exc),
            "candidates": [],
        }
    try:
        result = lookup_cell(observation, fetch_json=fetch_json)
    except Exception as exc:
        return {
            "status": "lookup_error",
            "source": "OpenCelliD via mcc-mnc.org",
            "message": f"Cell lookup unavailable: {type(exc).__name__}",
            "candidates": [],
            "attribution": API_ATTRIBUTION,
        }
    result["cell"] = observation["cell"]
    result["mcc"] = observation["mcc"]
    result["mnc"] = observation["mnc"]
    return result
