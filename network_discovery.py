#!/usr/bin/env python3
"""Config-scoped private AP discovery and optional Nmap fingerprinting."""
from __future__ import annotations
import ipaddress,re,shutil,subprocess,time
APPROVED_NETWORKS={};NETWORK_LABELS={};NETWORK_GATEWAYS={}
def configure_scope(networks,labels=None,gateways=None):
 global APPROVED_NETWORKS,NETWORK_LABELS,NETWORK_GATEWAYS
 if not isinstance(networks,dict) or not 1<=len(networks)<=8:raise ValueError('Configure one to eight AP networks.')
 valid={}
 for iface,subnet in networks.items():
  if not isinstance(iface,str) or not re.fullmatch(r'[A-Za-z0-9_.:-]{1,32}',iface):raise ValueError('Invalid interface.')
  n=ipaddress.ip_network(subnet,strict=False)
  if not isinstance(n,ipaddress.IPv4Network) or not n.is_private or not 16<=n.prefixlen<=30:raise ValueError('Only private IPv4 AP networks /16 through /30 are allowed.')
  valid[iface]=str(n)
 if len(set(valid.values()))!=len(valid):raise ValueError('Duplicate AP networks.')
 APPROVED_NETWORKS=valid;NETWORK_LABELS={k:str((labels or {}).get(k) or k)[:80] for k in valid};NETWORK_GATEWAYS={}
 for k,v in (gateways or {}).items():
  try:a=ipaddress.ip_address(v)
  except ValueError:continue
  if k in valid and isinstance(a,ipaddress.IPv4Address) and a in ipaddress.ip_network(valid[k]):NETWORK_GATEWAYS[k]=str(a)
def validate_scan_interfaces(xs):
 if not isinstance(xs,list) or not xs or len(xs)>len(APPROVED_NETWORKS) or len(set(xs))!=len(xs) or any(x not in APPROVED_NETWORKS for x in xs):return None
 return sorted(xs)
def fingerprint_scope(value):
 try:a=ipaddress.ip_address(value)
 except ValueError:return None
 if not isinstance(a,ipaddress.IPv4Address):return None
 for iface,sub in APPROVED_NETWORKS.items():
  n=ipaddress.ip_network(sub);gw=ipaddress.ip_address(NETWORK_GATEWAYS[iface]) if iface in NETWORK_GATEWAYS else None
  if a in n and a not in (n.network_address,n.broadcast_address,gw):return {'ip':str(a),'interface':iface}
 return None
def _run(args,timeout=15):
 try:
  p=subprocess.run(args,stdin=subprocess.DEVNULL,capture_output=True,text=True,timeout=timeout,env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C'})
  out=p.stdout or ''
  return p.returncode,out[:131072] if len(out.encode(errors='replace'))<=131072 else 'Output limit exceeded.'
 except (OSError,subprocess.TimeoutExpired) as e:return 1,str(e)[:240]
def tool_inventory():
 names={'arp-scan':'Scoped ARP discovery','nmap':'OS/service fingerprinting','p0f':'Passive OS fingerprinting','arpwatch':'MAC/IP change events','avahi-browse':'mDNS discovery'}
 return {'tools':[{'name':n,'purpose':p,'installed':bool(shutil.which(n,path='/usr/sbin:/usr/bin:/sbin:/bin'))} for n,p in names.items()],'scan_policy':'Only configured private AP interfaces are eligible.'}
def scan_interface(iface,timeout=12):
 if iface not in APPROVED_NETWORKS:raise ValueError('Interface outside configured AP scope.')
 b=shutil.which('arp-scan',path='/usr/sbin:/usr/bin:/sbin:/bin')
 if not b:return {'ok':False,'interface':iface,'error':'arp-scan is not installed.','devices':[]}
 rc,out=_run([b,'--interface='+iface,'--localnet','--retry=1','--timeout=500'],min(max(timeout,2),20));net=ipaddress.ip_network(APPROVED_NETWORKS[iface]);rows=[];seen=set()
 for line in out.splitlines()[:1500]:
  p=line.split()
  if len(p)<2:continue
  try:a=ipaddress.ip_address(p[0])
  except ValueError:continue
  m=p[1].lower()
  if a in net and re.fullmatch(r'(?:[0-9a-f]{2}:){5}[0-9a-f]{2}',m) and (str(a),m) not in seen:seen.add((str(a),m));rows.append({'ip':str(a),'mac':m,'interface':iface,'discovery_source':'arp-scan'})
 return {'ok':rc==0,'interface':iface,'network':str(net),'devices':rows[:512],'output':out[-3000:]}
def scan_configured_networks(interfaces=None):
 xs=validate_scan_interfaces(interfaces or list(APPROVED_NETWORKS))
 if not xs:return {'ok':False,'error':'No configured AP interfaces selected.'}
 return {'ok':True,'timestamp':time.time(),'results':[scan_interface(x) for x in xs]}
def fingerprint_device(address):
 scope=fingerprint_scope(address)
 if not scope:return {'ok':False,'error':'Target outside configured private AP networks.'}
 b=shutil.which('nmap',path='/usr/sbin:/usr/bin:/sbin:/bin')
 if not b:return {'ok':False,'error':'nmap is not installed.'}
 rc,out=_run([b,'-n','-Pn','-O','-sV','--version-light','--max-retries','1','--host-timeout','30s',address],35)
 return {'ok':rc==0,'target':address,'scope':scope,'output':out[:12000],'confidence':'tool-reported; verify independently'}
def cached_scan_results(interface):return []
def passive_os_fingerprints(log_paths=None):return {}
def recent_arpwatch_events(limit=20):return {'ok':True,'events':[],'available':False,'message':'No arpwatch event collector configured.'}
