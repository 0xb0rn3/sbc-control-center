# SBC Control Center — LTE cell-location helper patch

This patch adds a small, dependency-free helper for resolving a ZLT X17U LTE serving
cell to a **best-effort cell-area estimate** using the MCC-MNC cell API (OpenCelliD data).

## What it does

- Accepts the X17U's `ECGI` or separate `MCC`, `MNC`, and `CELL_ID` fields.
- Converts the supplied X17U ECGI `6400503CE233` into MCC `640`, MNC `05`, ECI `0x3CE233` / decimal `3990067`.
- Looks up the full LTE ECI. It does not use PCI as a cell identifier.
- Returns `estimated`, `ambiguous`, `not_found`, or `lookup_error`.
- Does not select a location when multiple cells match and TAC is missing.
- Caches results in process memory for six hours.
- Does not use the SBC's public IP, VPN exit IP, IMEI, IMSI, ICCID, phone number, or router credentials.

## Important integration boundary

The helper expects the caller to obtain a **read-only router status snapshot** from the
local ZLT X17U/W154R Plus interface and pass that mapping to `resolve_from_router()`.
It does not log in to the router, alter radio/band settings, or guess undocumented CGI
paths. The current repository needs a small follow-up adapter/route to connect this helper
to its existing ambient dashboard UI. That adapter must run server-side on the K2B and
must not expose router credentials or raw subscriber identifiers to browsers.

Example:

```python
from ambient_location import resolve_from_router

# `router_status` must be the read-only status response from the local X17U.
location = resolve_from_router(router_status)
```

A returned coordinate is the estimated serving-cell area, not the K2B's exact physical
position. If there are multiple matches and no TAC, the result is `ambiguous`; do not
silently choose the first point.

## Attribution and network use

The API endpoint is `https://mcc-mnc.org/api/v1/cells`. Its cell data is sourced from
OpenCelliD and licensed CC BY-SA 4.0. Preserve the returned attribution when displaying
coordinates. The API's anonymous allowance is limited; the six-hour in-process cache
reduces repeated requests. Network access is required for the lookup.

## Apply

From the repository root:

```bash
git apply sbc-ambient-location.patch
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_ambient_location -v
```

The patch adds the helper and unit tests only. It intentionally does not change the live
portal routes or UI until the exact read-only ZLT status adapter and desired display surface
are verified on the user's router.
