#!/usr/bin/env python3
"""Read-only Linux wireless adapter, PHY and station inventory."""
from __future__ import annotations
import re,shutil,subprocess
from pathlib import Path
def _run(args,timeout=4):
 try:
  p=subprocess.run(args,stdin=subprocess.DEVNULL,capture_output=True,text=True,timeout=timeout,env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C'})
  return p.stdout[:24000] if p.returncode==0 else ''
 except (OSError,subprocess.TimeoutExpired):return ''
def station_inventory(interfaces=()):
 iw=shutil.which('iw',path='/usr/sbin:/usr/bin:/sbin:/bin');out=[]
 if not iw:return out
 for iface in interfaces[:8]:
  cur=None
  for line in _run([iw,'dev',iface,'station','dump'],3).splitlines():
   m=re.match(r'Station\s+([0-9a-fA-F:]{17})',line)
   if m:
    if cur:out.append(cur)
    cur={'mac':m.group(1).lower(),'radio':iface,'associated':True,'discovery_source':'Wi-Fi station table'}
   elif cur:
    m=re.match(r'\s*(signal|signal avg|tx bitrate|rx bitrate|inactive time|connected time):\s*(.+)',line)
    if m:cur[m.group(1).replace(' ','_')]=m.group(2)[:80]
  if cur:out.append(cur)
 return out[:256]
def status(interfaces=()):
 iw=shutil.which('iw',path='/usr/sbin:/usr/bin:/sbin:/bin')
 if not iw:return {'ok':True,'available':False,'error':'iw is not installed.','adapters':[]}
 dev=_run([iw,'dev']);rows=[];cur=None
 for line in dev.splitlines():
  m=re.match(r'\s*Interface\s+(\S+)',line)
  if m:
   if cur:rows.append(cur)
   name=m.group(1);root=Path('/sys/class/net')/name;cur={'name':name,'interface':name,'present':root.exists(),'driver':None,'state':'unknown','phy':None,'type':'unknown','channel':None,'stations':station_inventory((name,))}
  if cur:
   m=re.search(r'\bwiphy\s+(\d+)',line)
   if m:cur['phy']='phy'+m.group(1)
   m=re.search(r'\btype\s+(\S+)',line)
   if m:cur['type']=m.group(1)
   m=re.search(r'channel\s+(\d+)\s+\((\d+)\s+MHz\)',line)
   if m:cur['channel']={'number':int(m.group(1)),'mhz':int(m.group(2))}
 if cur:rows.append(cur)
 if interfaces:rows=[x for x in rows if x['name'] in interfaces]
 for x in rows:
  root=Path('/sys/class/net')/x['name']
  try:x['state']=(root/'operstate').read_text().strip();x['driver']=(root/'device/driver').resolve().name
  except OSError:pass
  raw=_run([iw,'phy',x['phy'],'info'],5) if x.get('phy') else ''
  modes=re.findall(r'^\s*\*\s*(.+)$',raw,re.M)
  combos=re.findall(r'^\s*\*\s*#\{[^\n]+$',raw,re.M)
  x['phy_capabilities']={'supported_modes':modes[:32],'interface_combinations':combos[:16],'monitor_mode_supported':any(m.lower()=='monitor' for m in modes),'ap_mode_supported':any(m.lower()=='ap' for m in modes),'ap_monitor_concurrent':None,'phy_info_available':bool(raw)}
  x['wireless']={'phy':x.get('phy'),'type':x.get('type'),'channel':x.get('channel')}
 return {'ok':True,'available':True,'adapters':rows,'note':'Read-only. No interface mode or channel is changed.'}
