# SBC Control Center — ambient dashboard and router location

The /living-room display now includes a moving analogue clock, East Africa digital date/time, city weather, world clocks, USD exchange rates and technology headlines. It preserves the wallpaper slideshow and quote feed.

Router configuration: create `/etc/sbc-control-center/router.json` using `sudoedit`:

```json
{
  "host": "192.168.1.1",
  "username": "admin",
  "password": "YOUR_ROUTER_ADMIN_PASSWORD"
}
```

Then apply ownership and mode (adjust the group if the portal group has a custom name):

```bash
sudo chown root:sbc-control-center /etc/sbc-control-center/router.json
sudo chmod 0640 /etc/sbc-control-center/router.json
sudo systemctl restart sbc-control-center-web
```

The K2B reads ZLT X17U network status only. It does not change router settings or expose credentials, WAN IP or subscriber IDs to the browser. Cell records are queried by MCC/MNC/ECI and TAC when available. A single result is shown as a serving-cell area estimate; ambiguous matches are never silently selected. When cell lookup has no unique coordinate, only the public WAN IP reported by the ZLT router may be used as a coarse fallback. Private/CGNAT addresses are skipped; the K2B's public/VPN exit IP is never geolocated.

The page shows local weather when a coordinate is available, plus the 14 regional cities in all cases. Data sources: Open-Meteo weather (CC BY 4.0), ExchangeRate-API, publisher RSS feeds from TechCrunch, The Verge, Ars Technica and BBC Technology. Cell map attribution: OpenCelliD, CC BY-SA 4.0. All ambient data is server-side cached for three minutes; router status is cached for 45 seconds.

`/api/ambient` is public on the trusted LAN because the standby screen is sign-in-free. It is rate-limited and returns display-safe data only. Keep HTTPS/8443 on the LAN and never forward it to the public internet.

Run:

```bash
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_ambient_location tests.test_ambient_data -v
python3 -m py_compile ambient_location.py zlt_readonly.py ambient_data.py web.py
```

Protocol acknowledgement: the ZLT endpoint identifiers and token login flow were checked against [Mevhare/airtel-odu-app](https://github.com/Mevhare/airtel-odu-app), an MIT-licensed project. This repository implements a separate read-only adapter. See [upstream licence](https://github.com/Mevhare/airtel-odu-app/blob/master/LICENSE).
