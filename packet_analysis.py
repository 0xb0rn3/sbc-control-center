#!/usr/bin/env python3
"""Bounded offline TShark analysis of private application-owned captures."""
from __future__ import annotations
import os,shutil,subprocess,collections,csv,io
from pathlib import Path
CAPTURE_DIR=Path('/var/lib/sbc-control-center/captures');MAX_PCAP_BYTES=32*1024*1024
def tool_inventory():
 names={'tshark':'Protocol dissection','dumpcap':'Packet capture','capinfos':'Capture metadata','tcpdump':'Packet inspection','zeek':'Network monitoring','suricata':'IDS/IPS'}
 return {'ok':True,'tools':[{'name':n,'purpose':p,'available':bool(shutil.which(n,path='/usr/sbin:/usr/bin:/sbin:/bin'))} for n,p in names.items()],'engine':'AF_PACKET metadata plus offline TShark analysis'}
def _validated_capture(value):
 if not isinstance(value,str) or not value:raise ValueError('No capture selected.')
 base=CAPTURE_DIR.resolve(strict=True);p=Path(value)
 if p.is_symlink():raise ValueError('Capture symlink rejected.')
 p=p.resolve(strict=True);st=p.stat()
 if p.parent!=base or p.suffix!='.pcapng' or not p.is_file() or st.st_uid!=0 or st.st_mode&0o077 or not 0<st.st_size<=MAX_PCAP_BYTES:raise ValueError('Capture must be root-owned, private and at most 32 MiB.')
 return p
def analyse_capture(value):
 if os.geteuid()!=0:return {'ok':False,'error':'TShark requires the privileged agent.'}
 b=shutil.which('tshark',path='/usr/sbin:/usr/bin:/sbin:/bin')
 if not b:return {'ok':False,'error':'TShark is not installed.'}
 try:p=_validated_capture(value)
 except (OSError,ValueError) as e:return {'ok':False,'error':str(e)}
 fields=['frame.number','frame.time_epoch','frame.protocols','ip.src','ipv6.src','ip.dst','ipv6.dst','tcp.srcport','udp.srcport','tcp.dstport','udp.dstport','dns.qry.name','tls.handshake.extensions_server_name','frame.len']
 args=[b,'-n','-r',str(p),'-c','5000','-T','fields','-E','separator=,','-E','quote=d']
 for f in fields:args+=['-e',f]
 try:
  x=subprocess.run(args,stdin=subprocess.DEVNULL,capture_output=True,timeout=15,env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C','HOME':'/nonexistent'})
  if len(x.stdout)>2*1024*1024:return {'ok':False,'error':'Analysis output exceeds 2 MiB.'}
  if x.returncode:return {'ok':False,'error':x.stderr.decode(errors='replace')[:500]}
  rows=list(csv.DictReader(io.StringIO(x.stdout.decode(errors='replace'))));counts=collections.Counter(r.get('frame.protocols','') for r in rows)
  return {'ok':True,'capture':p.name,'packets_analysed':len(rows),'protocols':counts.most_common(30),'fields':rows[:500],'payloads_returned':False}
 except subprocess.TimeoutExpired:return {'ok':False,'error':'TShark exceeded 15-second limit.'}
 except OSError as e:return {'ok':False,'error':str(e)[:240]}
