#!/usr/bin/env python3
"""Local device identity with private/randomized MAC safeguards."""
from __future__ import annotations
import csv,json,re,ipaddress,subprocess,shutil,tempfile,os
from pathlib import Path
from typing import Any
STATE=Path('/var/lib/sbc-control-center/network');LABELS=STATE/'device-labels.json'
OUI=(Path('/usr/share/ieee-data/oui.csv'),Path('/var/lib/ieee-data/oui.csv'),STATE/'ieee-data/oui.csv')
def normalize_mac(v:Any)->str|None:
 return v.strip().lower().replace('-',':') if isinstance(v,str) and re.fullmatch(r'(?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}',v.strip()) else None
def mac_properties(v:Any)->dict[str,Any]:
 m=normalize_mac(v)
 if not m:return {'valid':False,'kind':'invalid','oui_lookup_allowed':False}
 b=int(m[:2],16);local=bool(b&2);multi=bool(b&1)
 return {'valid':True,'locally_administered':local,'multicast':multi,'kind':'multicast/group' if multi else 'locally administered (private/randomized or manual)' if local else 'globally administered','oui_lookup_allowed':not local and not multi}
def _db():
 out={}
 for p in OUI:
  try:
   with p.open(encoding='utf-8-sig',errors='replace',newline='') as f:
    for row in csv.DictReader(f):
     k=re.sub('[^0-9a-f]','',str(row.get('Assignment') or row.get('OUI') or '').lower());v=str(row.get('Organization Name') or row.get('Organization') or '').strip()
     if len(k) in (6,7,9) and v:out[k]=v[:120]
  except OSError:pass
 return out
def lookup_vendor(v,database=None):
 m=normalize_mac(v);props=mac_properties(m)
 if not m or not props.get('oui_lookup_allowed'):return {'vendor':None,'registry':None,'mac_properties':props}
 db=database if database is not None else _db();x=m.replace(':','')
 for n in (9,7,6):
  if x[:n] in db:return {'vendor':db[x[:n]],'registry':{6:'MA-L',7:'MA-M',9:'MA-S'}[n],'mac_properties':props}
 return {'vendor':None,'registry':None,'mac_properties':props}
def load_labels(path=LABELS):
 try:
  if path.is_symlink() or path.stat().st_mode&0o077:return {}
  d=json.loads(path.read_text());return {normalize_mac(k):v[:64] for k,v in d.items() if normalize_mac(k) and isinstance(v,str)} if isinstance(d,dict) else {}
 except (OSError,ValueError,TypeError):return {}
def _save(d,path):
 path.parent.mkdir(parents=True,exist_ok=True,mode=0o700);fd,tmp=tempfile.mkstemp(prefix='.labels-',dir=path.parent)
 try:
  with os.fdopen(fd,'w') as f:json.dump(d,f);f.flush();os.fsync(f.fileno())
  os.chmod(tmp,0o600);os.replace(tmp,path)
 finally:
  try:os.unlink(tmp)
  except FileNotFoundError:pass
def set_label(mac,label,path=LABELS):
 m=normalize_mac(mac)
 if not m or not isinstance(label,str) or not label.strip() or len(label)>64 or any(ord(c)<32 for c in label):return {'ok':False,'error':'Invalid MAC or label.'}
 d=load_labels(path);d[m]=label.strip();_save(d,path);return {'ok':True,'mac':m,'label':label.strip()}
def remove_label(mac,path=LABELS):
 m=normalize_mac(mac)
 if not m:return {'ok':False,'error':'Invalid MAC.'}
 d=load_labels(path);d.pop(m,None);_save(d,path);return {'ok':True,'mac':m}
def discover_neighbours(interface,subnet):
 try:net=ipaddress.ip_network(subnet,strict=False)
 except ValueError:return []
 ip=shutil.which('ip',path='/usr/sbin:/usr/bin:/sbin:/bin')
 if not ip:return []
 try:p=subprocess.run([ip,'-j','neigh','show','dev',interface],capture_output=True,text=True,timeout=3);rows=json.loads(p.stdout) if p.returncode==0 else []
 except (OSError,ValueError,subprocess.TimeoutExpired):return []
 out=[]
 for r in rows[:512]:
  try:a=ipaddress.ip_address(r.get('dst',''))
  except ValueError:continue
  m=normalize_mac(r.get('lladdr'))
  if a in net and m:out.append({'ip':str(a),'mac':m,'state':r.get('state'),'associated':False,'radio':interface,'discovery_source':'kernel neighbour table'})
 return out
def enrich_client(c,database=None,labels=None):
 m=normalize_mac(c.get('mac'));v=lookup_vendor(m,database);h=str(c.get('hostname') or '').lower();kind='unknown';conf='low';ev=[]
 for keys,k in [(('iphone','ipad','android','galaxy'),'mobile'),(('tv','vidaa','roku','bravia','samsung'),'smart television'),(('laptop','desktop','thinkpad','arxos'),'computer')]:
  if any(x in h for x in keys):kind=k;conf='medium';ev=['DHCP hostname hint'];break
 return {**c,'mac':m,'mac_kind':v['mac_properties'].get('kind'),'mac_locally_administered':v['mac_properties'].get('locally_administered',False),'mac_vendor':v['vendor'],'mac_vendor_registry':v['registry'],'identity_label':(labels or load_labels()).get(m) if m else None,'device_type':kind,'device_type_confidence':conf,'identity_confidence':'medium' if v['vendor'] else conf,'identity_evidence':ev+(['IEEE address-block assignee'] if v['vendor'] else [])}
def enrich_clients(rows,**kwargs):
 merged={}
 for r in rows:
  if not isinstance(r,dict):continue
  m=normalize_mac(r.get('mac'));key=m or ('ip:'+str(r.get('ip')) if r.get('ip') else None)
  if key:merged.setdefault(key,{}).update(r)
 labels=load_labels();db=kwargs.get('database') or _db()
 return [enrich_client(x,db,labels) for x in merged.values()]
def remember_observation(*a,**k):return None
def recent_observations(*a,**k):return []
