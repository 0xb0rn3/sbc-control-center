#!/usr/bin/env python3
"""Config-scoped network intelligence, capture and DNS integration."""
from __future__ import annotations
import ipaddress,json,re,time
from pathlib import Path
from typing import Any
import device_intelligence,dns_filter,network_discovery,packet_analysis,packet_monitor,wireless_adapter
CONFIG_PATH=Path('/etc/sbc-control-center/config.json');DNS_SCOPE_PATH=Path('/etc/sbc-control-center/dns.json');LEASE_FALLBACK=Path('/var/lib/misc/dnsmasq.leases')
_config={};_networks={};_addresses=set();_capture={};_upstreams=set();_monitor=None
def configure(config):
 global _config,_networks,_addresses,_capture,_upstreams,_monitor
 if not isinstance(config,dict):raise ValueError('Host network config unavailable.')
 nets={};addresses=set();capture={}
 for suffix in ('','2'):
  ik='ap_interface' if not suffix else 'ap2_interface';sk='ap_subnet' if not suffix else 'ap2_subnet';ak='ap_ip' if not suffix else 'ap2_ip'
  iface=config.get(ik);sub=config.get(sk);addr=config.get(ak)
  if not isinstance(iface,str) or not re.fullmatch(r'[A-Za-z0-9_.:-]{1,32}',iface) or not isinstance(sub,str):continue
  n=ipaddress.ip_network(sub,strict=False);a=ipaddress.ip_address(addr) if isinstance(addr,str) else None
  if not isinstance(n,ipaddress.IPv4Network) or not n.is_private or not 16<=n.prefixlen<=30 or not isinstance(a,ipaddress.IPv4Address) or a not in n:raise ValueError('AP scope must be configured private IPv4 networks.')
  if iface in nets or str(n) in nets.values():raise ValueError('Duplicate AP interface or subnet.')
  nets[iface]=str(n);addresses.add(str(a));capture[iface]='AP · '+str(config.get('ap_ssid' if not suffix else 'ap2_ssid') or iface)[:48]
 if not nets:raise ValueError('No valid AP networks configured.')
 vpn=config.get('vpn_interface')
 if isinstance(vpn,str) and re.fullmatch(r'[A-Za-z0-9_.:-]{1,32}',vpn) and vpn not in capture:capture[vpn]='VPN tunnel'
 upstream=set()
 try:
  d=json.loads(DNS_SCOPE_PATH.read_text())
  for v in d.get('upstreams',[])[:16]:
   try:upstream.add(str(ipaddress.ip_address(v)))
   except ValueError:pass
 except (OSError,ValueError,TypeError):pass
 lease=config.get('dhcp_lease_file') or str(LEASE_FALLBACK)
 if not isinstance(lease,str) or not lease.startswith('/var/lib/') or '..' in Path(lease).parts:lease=str(LEASE_FALLBACK)
 _config=dict(config);_networks=nets;_addresses=addresses;_capture=capture;_upstreams=upstream
 _monitor=packet_monitor.PacketMonitor(lease_path=Path(lease))
 network_discovery.configure_scope(nets,capture,{k:config[v] for k,v in ((config.get('ap_interface'),'ap_ip'),(config.get('ap2_interface'),'ap2_ip')) if k in nets})
 return {'ap_networks':nets,'capture_interfaces':capture,'configured_dns_upstreams':sorted(upstream)}
def _ensure():
 if _monitor:return
 try:configure(json.loads(CONFIG_PATH.read_text()))
 except (OSError,ValueError) as e:raise RuntimeError('Network config unavailable.') from e
def validate_scan_interfaces(xs):_ensure();return network_discovery.validate_scan_interfaces(xs)
def validate_capture_interfaces(xs):
 _ensure()
 return sorted(xs) if isinstance(xs,list) and 1<=len(xs)<=4 and len(set(xs))==len(xs) and all(isinstance(x,str) and x in _capture for x in xs) else None
def validate_fingerprint_address(v):_ensure();return str(v) if network_discovery.fingerprint_scope(v) else None
def inventory():
 _ensure();leases=packet_monitor._load_leases(Path(_config.get('dhcp_lease_file') or LEASE_FALLBACK));rows=[]
 for iface,sub in _networks.items():rows.extend(device_intelligence.discover_neighbours(iface,sub))
 rows.extend({'ip':ip,**x,'associated':False,'discovery_source':'DHCP lease'} for ip,x in leases.items())
 rows.extend(wireless_adapter.station_inventory(tuple(_networks)))
 clients=device_intelligence.enrich_clients(rows)
 return {'ok':True,'timestamp':time.time(),'clients':clients[:512],'client_count':len(clients),'wireless':wireless_adapter.status(tuple(_networks)),'adapters':packet_monitor.adapter_inventory(_capture),'discovery_tools':network_discovery.tool_inventory(),'packet_tools':packet_analysis.tool_inventory(),'dns_filter':dns_filter.status(),'passive_fingerprints':{},'capture_scope':{'interfaces':_capture,'ap_networks':_networks,'mode':'routed IP metadata capture; Wi-Fi monitor mode is never enabled automatically'}}
def scan(interfaces=None):
 _ensure();xs=list(_networks) if interfaces is None else network_discovery.validate_scan_interfaces(interfaces)
 return network_discovery.scan_configured_networks(xs) if xs else {'ok':False,'error':'Select only configured AP interfaces.'}
def fingerprint(address):
 _ensure()
 if not network_discovery.fingerprint_scope(address):return {'ok':False,'error':'Target outside configured private AP networks.'}
 return network_discovery.fingerprint_device(address)
def capture_start(duration_seconds,interfaces,save_pcap=False):
 _ensure()
 if not validate_capture_interfaces(interfaces):return {'ok':False,'error':'Capture interface outside configured allowlist.'}
 if not isinstance(save_pcap,bool):return {'ok':False,'error':'Invalid PCAPNG option.'}
 if isinstance(duration_seconds,bool) or not isinstance(duration_seconds,int):return {'ok':False,'error':'Invalid capture duration.'}
 return _monitor.start(duration_seconds,interfaces,_capture,tuple(_networks.values()),save_pcap,_networks,_addresses,_upstreams)
def capture_stop():_ensure();return _monitor.stop()
def capture_snapshot(after=0,limit=200):
 _ensure();r=_monitor.snapshot(after,limit);r['dns_bypass_events']=[x['dns_bypass_indicator'] for x in r['events'] if isinstance(x.get('dns_bypass_indicator'),dict)]
 c=r['capture']
 if c.get('pcapng_path'):c['pcapng_name']=Path(c['pcapng_path']).name;c.pop('pcapng_path',None)
 return r
def analyse_capture(name):
 _ensure()
 if not isinstance(name,str) or Path(name).name!=name or not re.fullmatch(r'sbc-control-center-[0-9]{8}T[0-9]{6}Z-[0-9]+\.pcapng',name):return {'ok':False,'error':'Invalid capture identifier.'}
 return packet_analysis.analyse_capture(str(packet_monitor.CAPTURE_DIR/name))
def dns_status():return dns_filter.status()
def dns_query_log(limit=50):
 try:return dns_filter.query_log(int(limit))
 except Exception as e:return {'ok':False,'error':str(e)[:240]}
def set_client_label(mac,label):return device_intelligence.set_label(mac,label)
def remove_client_label(mac):return device_intelligence.remove_label(mac)
def get_state():_ensure();return _monitor.snapshot(0,0)['capture']
