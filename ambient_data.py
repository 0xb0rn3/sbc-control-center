"""Cached server-side data feed for the public ambient / living-room display."""
from __future__ import annotations

import concurrent.futures
import datetime as dt
import email.utils
import ipaddress
import json
import threading
import time
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from typing import Any

import ambient_location
import sbc_site
import zlt_readonly

CACHE_SECONDS = 180
_cache_lock = threading.Lock()
_cache: tuple[float, dict[str, Any]] | None = None
_fetch_pool = concurrent.futures.ThreadPoolExecutor(max_workers=18, thread_name_prefix="ambient")

CITIES = [
    {"name":"Dar es Salaam","country":"Tanzania","lat":-6.7924,"lon":39.2083,"tz":"Africa/Dar_es_Salaam"},
    {"name":"Arusha","country":"Tanzania","lat":-3.3869,"lon":36.6830,"tz":"Africa/Dar_es_Salaam"},
    {"name":"Mwanza","country":"Tanzania","lat":-2.5164,"lon":32.9175,"tz":"Africa/Dar_es_Salaam"},
    {"name":"Dodoma","country":"Tanzania","lat":-6.1630,"lon":35.7516,"tz":"Africa/Dar_es_Salaam"},
    {"name":"Zanzibar City","country":"Tanzania","lat":-6.1659,"lon":39.2026,"tz":"Africa/Dar_es_Salaam"},
    {"name":"Mbeya","country":"Tanzania","lat":-8.9094,"lon":33.4608,"tz":"Africa/Dar_es_Salaam"},
    {"name":"Nairobi","country":"Kenya","lat":-1.2921,"lon":36.8219,"tz":"Africa/Nairobi"},
    {"name":"Mombasa","country":"Kenya","lat":-4.0435,"lon":39.6682,"tz":"Africa/Nairobi"},
    {"name":"Kampala","country":"Uganda","lat":0.3476,"lon":32.5825,"tz":"Africa/Kampala"},
    {"name":"Kigali","country":"Rwanda","lat":-1.9441,"lon":30.0619,"tz":"Africa/Kigali"},
    {"name":"Bujumbura","country":"Burundi","lat":-3.3614,"lon":29.3599,"tz":"Africa/Bujumbura"},
    {"name":"Addis Ababa","country":"Ethiopia","lat":9.0300,"lon":38.7400,"tz":"Africa/Addis_Ababa"},
    {"name":"Juba","country":"South Sudan","lat":4.8594,"lon":31.5713,"tz":"Africa/Juba"},
    {"name":"Mogadishu","country":"Somalia","lat":2.0469,"lon":45.3182,"tz":"Africa/Mogadishu"},
]
CURRENCIES = [
    ("TZS","Tanzanian shilling"),("KES","Kenyan shilling"),("UGX","Ugandan shilling"),
    ("RWF","Rwandan franc"),("BIF","Burundian franc"),("ETB","Ethiopian birr"),
    ("SSP","South Sudanese pound"),("SOS","Somali shilling"),
    ("EUR","Euro"),("GBP","British pound"),("CHF","Swiss franc"),
]
WORLD_CLOCKS = [
    ("Dar es Salaam","Africa/Dar_es_Salaam"),("Arusha","Africa/Dar_es_Salaam"),
    ("Mwanza","Africa/Dar_es_Salaam"),("Nairobi","Africa/Nairobi"),
    ("Mombasa","Africa/Nairobi"),("Kampala","Africa/Kampala"),("Kigali","Africa/Kigali"),
    ("Addis Ababa","Africa/Addis_Ababa"),("London","Europe/London"),
    ("Paris","Europe/Paris"),("Berlin","Europe/Berlin"),
]
NEWS_FEEDS = [
    ("TechCrunch","https://techcrunch.com/feed/"),
    ("The Verge","https://www.theverge.com/rss/index.xml"),
    ("Ars Technica","https://feeds.arstechnica.com/arstechnica/index"),
    ("BBC Technology","https://feeds.bbci.co.uk/news/technology/rss.xml"),
]
WEATHER_FIELDS = "temperature_2m,relative_humidity_2m,apparent_temperature,is_day,precipitation,weather_code,wind_speed_10m"
_WEATHER_LABELS = {
    0:"Clear",1:"Mainly clear",2:"Partly cloudy",3:"Overcast",
    45:"Fog",48:"Rime fog",51:"Light drizzle",53:"Drizzle",55:"Dense drizzle",
    56:"Freezing drizzle",57:"Heavy freezing drizzle",61:"Light rain",63:"Rain",
    65:"Heavy rain",66:"Freezing rain",67:"Heavy freezing rain",71:"Light snow",
    73:"Snow",75:"Heavy snow",77:"Snow grains",80:"Rain showers",81:"Showers",
    82:"Heavy showers",85:"Snow showers",86:"Heavy snow showers",95:"Thunderstorm",
    96:"Thunderstorm with hail",99:"Severe thunderstorm",
}


def _json(url: str, timeout: float = 5.0) -> dict[str, Any] | list[Any]:
    request = urllib.request.Request(url, headers={
        "User-Agent":"SBC-Control-Center/1.0 (+https://github.com/0xb0rn3/sbc-control-center)",
        "Accept":"application/json",
    })
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(request, timeout=timeout) as response:
        if response.status != 200:
            raise OSError(f"HTTP {response.status}")
        body = response.read(1024 * 1024)
    value = json.loads(body.decode("utf-8"))
    if not isinstance(value, (dict, list)):
        raise ValueError("Unexpected JSON response")
    return value


def _xml(url: str, timeout: float = 6.0) -> bytes:
    request = urllib.request.Request(url, headers={
        "User-Agent":"SBC-Control-Center/1.0",
        "Accept":"application/rss+xml, application/atom+xml, application/xml, text/xml",
    })
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(request, timeout=timeout) as response:
        return response.read(512 * 1024)


def _weather(locations: list[dict[str, Any]]) -> list[dict[str, Any]]:
    if not locations:
        return []
    lat = ",".join(str(row["lat"]) for row in locations)
    lon = ",".join(str(row["lon"]) for row in locations)
    query = urllib.parse.urlencode({
        "latitude":lat,"longitude":lon,"current":WEATHER_FIELDS,"timezone":"auto",
        "forecast_days":"1",
    })
    try:
        data = _json("https://api.open-meteo.com/v1/forecast?" + query, timeout=8)
        rows = data if isinstance(data, list) else [data]
        result = []
        for index, row in enumerate(rows):
            if index >= len(locations) or not isinstance(row, dict):
                continue
            current = row.get("current") or {}
            code = current.get("weather_code")
            result.append({
                "name":locations[index]["name"], "country":locations[index].get("country",""),
                "temperature_c":current.get("temperature_2m"),
                "feels_like_c":current.get("apparent_temperature"),
                "humidity_percent":current.get("relative_humidity_2m"),
                "wind_kmh":current.get("wind_speed_10m"),
                "precipitation_mm":current.get("precipitation"),
                "weather_code":code,
                "condition":_WEATHER_LABELS.get(code,"Weather unavailable"),
                "is_day":current.get("is_day"),
                "observed_at":current.get("time"),
            })
        return result
    except Exception:
        return []


def _fx() -> dict[str, Any]:
    try:
        data = _json("https://open.er-api.com/v6/latest/USD", timeout=6)
        rates = data.get("rates", {}) if isinstance(data, dict) else {}
        rows = [{"code":code,"name":name,"per_usd":rates.get(code)} for code,name in CURRENCIES]
        return {"base":"USD","updated":data.get("time_last_update_utc"),"rates":rows,
                "source":"ExchangeRate-API"} 
    except Exception:
        return {"base":"USD","updated":None,
                "rates":[{"code":code,"name":name,"per_usd":None} for code,name in CURRENCIES],
                "source":"ExchangeRate-API","unavailable":True}


def _parse_news_feed(source: str, url: str) -> list[dict[str, Any]]:
    try:
        root = ET.fromstring(_xml(url))
    except Exception:
        return []
    rows = []
    for item in root.findall(".//item")[:20]:
        title = (item.findtext("title") or "").strip()
        link = (item.findtext("link") or "").strip()
        published = (item.findtext("pubDate") or "").strip()
        if not title or not link:
            continue
        parsed = urllib.parse.urlparse(link)
        if parsed.scheme != "https" or not parsed.netloc:
            continue
        try:
            stamp = email.utils.parsedate_to_datetime(published).timestamp()
        except Exception:
            stamp = 0
        rows.append({"source":source,"title":title[:220],"url":link[:1200],
                     "published":published[:100],"timestamp":stamp})
    # Atom feeds are used by some providers.
    ns = {"a":"http://www.w3.org/2005/Atom"}
    for entry in root.findall(".//a:entry",ns)[:20]:
        title = (entry.findtext("a:title",default="",namespaces=ns) or "").strip()
        link_el = entry.find("a:link",ns)
        link = link_el.get("href","") if link_el is not None else ""
        published = entry.findtext("a:published",default="",namespaces=ns) or entry.findtext("a:updated",default="",namespaces=ns) or ""
        parsed = urllib.parse.urlparse(link)
        if not title or parsed.scheme != "https" or not parsed.netloc:
            continue
        try:
            stamp = dt.datetime.fromisoformat(published.replace("Z","+00:00")).timestamp()
        except Exception:
            stamp = 0
        rows.append({"source":source,"title":title[:220],"url":link[:1200],
                     "published":published[:100],"timestamp":stamp})
    return rows


def _news() -> list[dict[str, Any]]:
    futures = [_fetch_pool.submit(_parse_news_feed, name, url) for name,url in NEWS_FEEDS]
    rows = []
    for future in futures:
        try:
            rows.extend(future.result(timeout=8))
        except Exception:
            continue
    rows.sort(key=lambda item:item["timestamp"],reverse=True)
    return rows[:10]


def _router_location() -> tuple[dict[str, Any], str | None]:
    try:
        radio = zlt_readonly.network_info()
    except zlt_readonly.RouterUnavailable as exc:
        return ({"status":"unavailable","source":"ZLT X17U","message":str(exc),
                 "label":"Location not configured","confidence":"none"},None)

    result = ambient_location.resolve_from_router(radio)
    if result.get("status") == "estimated" and result.get("location"):
        point = result["location"]
        return ({
            "status":"estimated","source":"LTE cell tower",
            "message":"Serving-cell area estimate; not the router's exact position.",
            "label":"Approximate cellular location","confidence":"cell",
            "latitude":point["latitude"],"longitude":point["longitude"],
            "range_m":point.get("range_m"),
            "attribution":result.get("attribution",ambient_location.API_ATTRIBUTION),
        }, radio.get("wan_ip"))

    # Only the public WAN address reported by the ZLT router is eligible for
    # fallback. Never inspect the SBC's public address (which could be a VPN exit).
    return ({
        "status":result.get("status","not_found"),
        "source":"LTE cell lookup","message":result.get("message","Cell location unavailable."),
        "label":"Cell location unavailable","confidence":"none",
        "candidates":result.get("candidates",[]),
        "attribution":result.get("attribution",ambient_location.API_ATTRIBUTION),
    }, radio.get("wan_ip"))


def _router_wan_fallback(ip_value: str | None, previous: dict[str, Any]) -> dict[str, Any]:
    try:
        address = ipaddress.ip_address(str(ip_value or "").strip())
        if address.version != 4 or not address.is_global:
            return previous
        data = _json("https://ipwho.is/" + urllib.parse.quote(str(address),safe=""),timeout=4)
        if not isinstance(data,dict) or not data.get("success"):
            return previous
        lat,lon = float(data["latitude"]),float(data["longitude"])
        if not (-90 <= lat <= 90 and -180 <= lon <= 180):
            return previous
        return {
            "status":"coarse","source":"Router WAN IP",
            "message":"Approximate ISP network location from the router's public WAN address; not GPS.",
            "label":", ".join(x for x in (data.get("city"),data.get("region"),data.get("country")) if x) or "Approximate network location",
            "confidence":"ip","latitude":lat,"longitude":lon,
            "attribution":"IP location estimate provided by ipwho.is",
        }
    except Exception:
        return previous


def _snapshot() -> dict[str, Any]:
    location, router_wan_ip = _router_location()
    if location.get("status") != "estimated":
        location = _router_wan_fallback(router_wan_ip,location)

    local_weather = []
    if isinstance(location.get("latitude"),(float,int)) and isinstance(location.get("longitude"),(float,int)):
        local_weather = [{"name":location.get("label","Your area"),"country":"",
                          "lat":location["latitude"],"lon":location["longitude"]}]
    city_weather = _weather(CITIES)
    if local_weather:
        local_weather = _weather(local_weather)

    fx_future = _fetch_pool.submit(_fx)
    news_future = _fetch_pool.submit(_news)
    try: fx = fx_future.result(timeout=8)
    except Exception: fx = {"base":"USD","rates":[],"unavailable":True}
    try: news = news_future.result(timeout=9)
    except Exception: news = []

    return {
        "ok":True,"generated_at":int(time.time()),
        "location":location,
        "local_weather":local_weather,
        "city_weather":city_weather,
        "world_clocks":[{"name":name,"timezone":zone} for name,zone in WORLD_CLOCKS],
        "fx":fx,"news":news,
        "attribution":{
            "weather":"Weather data by Open-Meteo (CC BY 4.0).",
            "cell":ambient_location.API_ATTRIBUTION,
            "fx":"Exchange rates by ExchangeRate-API.",
            "news":"Headlines linked to their publishers.",
        },
    }


def snapshot(force: bool = False) -> dict[str, Any]:
    global _cache
    now = time.time()
    with _cache_lock:
        if not force and _cache and now - _cache[0] < CACHE_SECONDS:
            return dict(_cache[1])
    result = _snapshot()
    with _cache_lock:
        _cache = (now, result)
    return dict(result)
