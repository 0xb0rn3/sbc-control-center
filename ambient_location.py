"""Best-effort cell-tower geolocation for the SBC Control Center.

The cell database returns measured serving-cell areas, not device coordinates.
No SBC/VPN exit IP, subscriber identifier or router credential is used here.
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
_cache: dict[tuple[str, str, str, str, str], tuple[float, dict[str, Any]]] = {}
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
        number = int(text, 10)
    else:
        raise ValueError("Invalid LTE cell identity")
    if not 0 <= number < (1 << 28):
        raise ValueError("LTE ECI must be a 28-bit value")
    return number


def observation_from_router(info: dict[str, Any]) -> dict[str, str]:
    """Normalize ZLT X17U fields; interpret CELL_ID and ECGI suffixes as hex."""
    if not isinstance(info, dict):
        raise ValueError("Router information must be an object")

    mcc, mnc = info.get("MCC"), info.get("MNC")
    cell_value = info.get("CELL_ID") or info.get("cell_id")
    eci_value = info.get("ECI")
    ecgi = info.get("ECGI") or info.get("ecgi")
    area_value = info.get("TAC") or info.get("tac") or info.get("CELL_AREA")

    if ecgi:
        value = re.sub(r"[^0-9a-fA-F]", "", str(ecgi))
        if len(value) < 6:
            raise ValueError("ECGI is incomplete")
        mcc, mnc = value[:3], value[3:5]
        # The remaining 28-bit ECI in the ECGI is hexadecimal, including
        # numeric-only values such as 0001234.
        cell_number = int(value[5:], 16)
    elif cell_value:
        raw_cell = str(cell_value).strip()
        cell_number = int(raw_cell[2:], 16) if raw_cell.lower().startswith("0x") else int(raw_cell, 16)
    elif eci_value:
        cell_number = _cell_number(eci_value)
    else:
        raise ValueError("Router must provide LTE CELL_ID or ECGI")

    if not (mcc and mnc):
        raise ValueError("Router must provide MCC and MNC or a composite ECGI")
    if not 0 <= cell_number < (1 << 28):
        raise ValueError("LTE ECI must be a 28-bit value")

    result = {
        "mcc": _digits(mcc, "MCC", 3),
        "mnc": _digits(mnc, "MNC", 3),
        "cell": str(cell_number),
        "radio": "LTE",
    }
    if area_value not in (None, ""):
        area = str(area_value).strip()
        if area.lower().startswith("0x"):
            area = str(int(area, 16))
        if not area.isdigit() or len(area) > 8:
            raise ValueError("Invalid LTE tracking area code")
        result["area"] = area
    return result


def _request_json(url: str, timeout: float = 6.0) -> dict[str, Any]:
    request = urllib.request.Request(url, headers={
        "Accept": "application/json", "User-Agent": "SBC-Control-Center/1.0",
    })
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(request, timeout=timeout) as response:
        if response.status != 200:
            raise OSError(f"Cell lookup returned HTTP {response.status}")
        raw = response.read(256 * 1024)
    payload = json.loads(raw.decode("utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("Unexpected cell lookup response")
    return payload


def lookup_cell(observation: dict[str, str], fetch_json=_request_json) -> dict[str, Any]:
    """Look up a cell; return all candidate records and never guess between them."""
    mcc = _digits(observation.get("mcc"), "MCC", 3)
    mnc = _digits(observation.get("mnc"), "MNC", 3)
    cell = str(_cell_number(observation.get("cell")))
    radio = str(observation.get("radio", "LTE")).upper()
    area = str(observation.get("area", "")).strip()
    if radio not in ("LTE", "NR"):
        raise ValueError("Only LTE/NR cell lookup is supported")
    if area and (not area.isdigit() or len(area) > 8):
        raise ValueError("Invalid tracking area code")

    key = (mcc, mnc, cell, radio, area)
    now = time.time()
    with _cache_lock:
        cached = _cache.get(key)
        if cached and now - cached[0] < _CACHE_TTL:
            return dict(cached[1])

    params = {"mcc":mcc,"mnc":mnc,"cell":cell,"radio":radio}
    if area:
        params["area"] = area
    payload = fetch_json(API_URL + "?" + urllib.parse.urlencode(params))
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
            "latitude":lat,"longitude":lon,"range_m":row.get("range"),
            "samples":row.get("samples"),"area":row.get("area"),
            "last_seen":row.get("lastSeen"),"radio":row.get("radio",radio),
        })

    meta = payload.get("meta") if isinstance(payload.get("meta"),dict) else {}
    attribution = meta.get("attribution") or API_ATTRIBUTION
    if not candidates:
        result = {"status":"not_found","source":"OpenCelliD via mcc-mnc.org",
                  "message":"No measured location is available for this cell. This does not mean the cell does not exist.",
                  "candidates":[],"attribution":attribution}
    elif len(candidates) == 1:
        result = {"status":"estimated","source":"OpenCelliD via mcc-mnc.org",
                  "message":"Estimated serving-cell area, not the router's exact position.",
                  "location":candidates[0],"candidates":candidates,"attribution":attribution}
    else:
        result = {"status":"ambiguous","source":"OpenCelliD via mcc-mnc.org",
                  "message":"Multiple cell records match; no location was selected.",
                  "candidates":candidates,"attribution":attribution}
    with _cache_lock:
        _cache[key] = (now, result)
    return dict(result)


def resolve_from_router(info: dict[str, Any], fetch_json=_request_json) -> dict[str, Any]:
    try:
        observation = observation_from_router(info)
    except (TypeError, ValueError) as exc:
        return {"status":"unavailable","source":"ZLT router radio status",
                "message":str(exc),"candidates":[]}
    try:
        result = lookup_cell(observation, fetch_json=fetch_json)
    except Exception as exc:
        return {"status":"lookup_error","source":"OpenCelliD via mcc-mnc.org",
                "message":f"Cell lookup unavailable: {type(exc).__name__}",
                "candidates":[],"attribution":API_ATTRIBUTION}
    result.update({"cell":observation["cell"],"mcc":observation["mcc"],"mnc":observation["mnc"]})
    return result
