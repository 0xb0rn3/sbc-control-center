#!/usr/bin/env python3
"""Bounded Linux AF_PACKET metadata inspector with optional explicit PCAPNG."""
from __future__ import annotations
import collections,datetime as dt,ipaddress,os,re,socket,struct,subprocess,threading,time
from pathlib import Path
from typing import Any
import device_intelligence,wireless_adapter,dns_bypass_sensor,flow_telemetry
ETH_P_ALL=0x0003;ETH_P_ARP=0x0806;PACKET_OUTGOING=getattr(socket,'PACKET_OUTGOING',4)
SOL_PACKET=263;PACKET_STATISTICS=6
MAX_EVENTS=2500;MAX_FLOWS=2048;MAX_CAPTURE_SECONDS=600;MAX_PCAP_BYTES=32*1024*1024
CAPTURE_DIR=Path('/var/lib/sbc-control-center/captures');LEASE_FILE=Path('/var/lib/misc/dnsmasq.leases');CONNTRACK_FILE=Path('/proc/net/nf_conntrack')
DEFAULT_INTERFACES={};DEFAULT_SUBNETS=()
def _dns_name(data,offset):
 labels=[];pos=offset;seen=set();end=None
 for _ in range(64):
  if pos>=len(data):return None,offset
  n=data[pos]
  if n==0:
   if end is None:end=pos+1
   return '.'.join(labels)[:253],end
  if n&0xc0==0xc0:
   if pos+1>=len(data):return None,offset
   ptr=((n&0x3f)<<8)|data[pos+1]
   if ptr in seen or ptr>=len(data):return None,offset
   seen.add(ptr)
   if end is None:end=pos+2
   pos=ptr;continue
  if n&0xc0 or n>63 or pos+1+n>len(data):return None,offset
  label=data[pos+1:pos+1+n]
  if not label or any(x<33 or x>126 for x in label):return None,offset
  labels.append(label.decode('ascii','replace'));pos+=n+1
  if sum(map(len,labels))+len(labels)>253:return None,offset
 return None,offset
def _dns(payload):
 if len(payload)<12:return None,None,None,None
 flags=struct.unpack_from('!H',payload,2)[0];qname,off=_dns_name(payload,12)
 if not qname or off+4>len(payload):return None,None,None,None
 qtype=struct.unpack_from('!H',payload,off)[0]
 return qname,qtype,flags&15,bool(flags&0x800)
def _tls_sni(payload):
 try:
  if len(payload)<9 or payload[0]!=22:return None
  pos=5
  if payload[pos]!=1:return None
  pos+=4+2+32
  n=payload[pos];pos+=1+n
  sl=struct.unpack_from('!H',payload,pos)[0];pos+=2+sl
  cl=payload[pos];pos+=1+cl
  el=struct.unpack_from('!H',payload,pos)[0];pos+=2;end=min(len(payload),pos+el)
  while pos+4<=end:
   typ,size=struct.unpack_from('!HH',payload,pos);pos+=4
   if pos+size>end:return None
   if typ==0:
    ext=payload[pos:pos+size];ln=struct.unpack_from('!H',ext,0)[0];q=2
    while q+3<=min(len(ext),2+ln):
     nt=ext[q];sz=struct.unpack_from('!H',ext,q+1)[0];q+=3
     if q+sz>len(ext):return None
     if nt==0:return ext[q:q+sz].decode('ascii','ignore').lower()[:253]
     q+=sz
   pos+=size
 except (IndexError,struct.error,UnicodeError):return None
 return None
def decode_packet(data,packet_type=0,link_protocol=None):
 e={'timestamp':time.time(),'timestamp_ns':time.time_ns(),'direction':'outbound' if packet_type==PACKET_OUTGOING else 'inbound','bytes':len(data),'source_ip':None,'destination_ip':None,'source_port':None,'destination_port':None,'protocol':'OTHER','application':'Other','dns_query':None,'dns_qtype':None,'dns_rcode':None,'dns_response':None,'tls_sni':None,'ip_version':None}
 if not data:return e
 version=data[0]>>4;off=0;transport=0
 if version==4 and len(data)>=20:
  ihl=(data[0]&15)*4;total=struct.unpack_from('!H',data,2)[0] or len(data)
  if ihl<20 or ihl>len(data) or total<ihl:e['protocol']='IPv4 malformed';return e
  e.update(ip_version=4,source_ip=socket.inet_ntop(socket.AF_INET,data[12:16]),destination_ip=socket.inet_ntop(socket.AF_INET,data[16:20]))
  transport=data[9];off=ihl;end=min(len(data),total)
 elif version==6 and len(data)>=40:
  e.update(ip_version=6,source_ip=socket.inet_ntop(socket.AF_INET6,data[8:24]),destination_ip=socket.inet_ntop(socket.AF_INET6,data[24:40]))
  transport=data[6];off=40;end=min(len(data),40+struct.unpack_from('!H',data,4)[0])
  for _ in range(8):
   if transport in (0,43,60):
    if off+2>end:e['protocol']='IPv6 extension';return e
    nxt=data[off];sz=(data[off+1]+1)*8
   elif transport==44:
    if off+8>end:e['protocol']='IPv6 extension';return e
    nxt=data[off];sz=8
   elif transport==51:
    if off+2>end:e['protocol']='IPv6 extension';return e
    nxt=data[off];sz=(data[off+1]+2)*4
   else:break
   if sz<8 or off+sz>end:e['protocol']='IPv6 extension';return e
   transport=nxt;off+=sz
 else:
  if link_protocol in (ETH_P_ARP,socket.htons(ETH_P_ARP)) and len(data)>=28:
   op=struct.unpack_from('!H',data,6)[0];e.update(protocol='ARP',application='Address resolution',arp_operation=op,arp_sender_mac=':'.join(f'{x:02x}' for x in data[8:14]),arp_sender_ip=socket.inet_ntop(socket.AF_INET,data[14:18]),arp_target_mac=':'.join(f'{x:02x}' for x in data[18:24]),arp_target_ip=socket.inet_ntop(socket.AF_INET,data[24:28]))
  else:e['protocol']='Non-IP'
  return e
 p=data[off:end]
 if transport==6 and len(p)>=20:
  e['protocol']='TCP';sp,dp=struct.unpack_from('!HH',p,0);hlen=(p[12]>>4)*4
  if hlen<20 or hlen>len(p):return e
  app=p[hlen:];e.update(source_port=sp,destination_port=dp)
  if sp==53 or dp==53:
   e['application']='DNS';e['dns_query'],e['dns_qtype'],e['dns_rcode'],e['dns_response']=_dns(app)
  elif sp in (80,8080) or dp in (80,8080):e['application']='HTTP'
  elif sp in (443,8443) or dp in (443,8443):e['application']='TLS';e['tls_sni']=_tls_sni(app)
  elif sp==22 or dp==22:e['application']='SSH'
 elif transport==17 and len(p)>=8:
  e['protocol']='UDP';sp,dp=struct.unpack_from('!HH',p,0);app=p[8:];e.update(source_port=sp,destination_port=dp)
  if sp==53 or dp==53:e['application']='DNS';e['dns_query'],e['dns_qtype'],e['dns_rcode'],e['dns_response']=_dns(app)
  elif sp in (443,784,853,8853) or dp in (443,784,853,8853):e['application']='QUIC / encrypted transport'
  elif sp in (67,68) or dp in (67,68):e['application']='DHCP'
  elif sp==5353 or dp==5353:e['application']='mDNS';e['mdns_name']=_dns(app)[0]
  elif sp==1900 or dp==1900:e['application']='SSDP / UPnP'
 elif transport in (1,58):e['protocol']='ICMP' if transport==1 else 'ICMPv6';e['application']='Network control'
 else:e['protocol']=f'IP-{transport}'
 return e
def _load_leases(path=LEASE_FILE):
 out={}
 try:
  for line in path.read_text().splitlines()[:4096]:
   p=line.split()
   if len(p)>=4:
    m=device_intelligence.normalize_mac(p[1]);ip=p[2]
    if m:out[ip]={'mac':m,'hostname':p[3] if p[3]!='*' else None}
 except OSError:pass
 return out
class PcapngWriter:
 def __init__(self,interfaces,directory=CAPTURE_DIR,max_bytes=MAX_PCAP_BYTES):
  directory.mkdir(parents=True,exist_ok=True,mode=0o700);os.chmod(directory,0o700)
  stamp=dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%SZ');self.path=directory/f'sbc-control-center-{stamp}-{os.getpid()}.pcapng'
  fd=os.open(self.path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0),0o600);self.f=os.fdopen(fd,'wb',buffering=0)
  self.lock=threading.Lock();self.max=max_bytes;self.written=0;self.full=False;self.index={x:i for i,x in enumerate(interfaces)}
  self._block(0x0A0D0D0A,struct.pack('<IHHq',0x1A2B3C4D,1,0,-1))
  for name in interfaces:
   v=name.encode()[:64];pad=b'\0'*((-len(v))%4);self._block(1,struct.pack('<HHI',101,0,65535)+struct.pack('<HH',2,len(v))+v+pad+struct.pack('<HH',0,0))
 def _block(self,kind,body):
  n=12+len(body);self.f.write(struct.pack('<II',kind,n)+body+struct.pack('<I',n));self.written+=n
 def write_packet(self,iface,data,epoch_ns):
  if not data or data[0]>>4 not in (4,6):return False
  with self.lock:
   if self.full or self.f.closed or iface not in self.index:return False
   n=min(len(data),65535);micros=epoch_ns//1000;body=struct.pack('<IIIII',self.index[iface],micros>>32,micros&0xffffffff,n,n)+data[:n]+b'\0'*((-n)%4)
   if self.written+12+len(body)>self.max:self.full=True;return False
   self._block(6,body);return True
 def close(self):
  with self.lock:
   if not self.f.closed:self.f.flush();os.fsync(self.f.fileno());self.f.close()
 @property
 def size(self):return self.written
class PacketMonitor:
 def __init__(self,ring_size=MAX_EVENTS,conntrack_path=CONNTRACK_FILE,lease_path=LEASE_FILE):
  self.lock=threading.RLock();self.events=collections.deque(maxlen=ring_size);self.flow_tracker=flow_telemetry.FlowRateTracker();self.flow_event_emit=collections.OrderedDict();self.lease_path=lease_path;self.conntrack_path=conntrack_path
  self.stop_event=threading.Event();self.threads=[];self.sockets=[];self.writer=None;self.active=False;self.started=None;self.stop_at=None;self.duration=0
  self.interfaces=[];self.allowed={};self.subnets=();self.scope={};self.local_dns=set();self.upstreams=set();self.counts={};self.errors=[];self.overwritten=0;self.next_id=0;self.last_packet_at=None;self.last_pcap=None;self.last_pcap_bytes=0
  self.leases={};self.identities={}
 def _refresh_maps(self):
  self.leases=_load_leases(self.lease_path);rows=[]
  for iface,subnet in self.scope.items():rows.extend(device_intelligence.discover_neighbours(iface,subnet))
  rows.extend({'ip':ip,**row,'associated':False,'discovery_source':'DHCP lease'} for ip,row in self.leases.items())
  rows.extend(wireless_adapter.station_inventory(tuple(self.scope)))
  self.identities={r.get('ip'):r for r in device_intelligence.enrich_clients(rows) if r.get('ip')}
 def _event(self,iface,packet_type,link,data,epoch_ns):
  e=decode_packet(data,packet_type,link);e['timestamp_ns']=epoch_ns;e['timestamp']=epoch_ns/1e9;e['interface']=iface;e['path']=self.allowed.get(iface,'Other')
  client=None;remote=None
  for subnet in self.subnets:
   try:n=ipaddress.ip_network(subnet)
   except ValueError:continue
   if e.get('source_ip') and ipaddress.ip_address(e['source_ip']) in n:client=e['source_ip'];remote=e.get('destination_ip');break
   if e.get('destination_ip') and ipaddress.ip_address(e['destination_ip']) in n:client=e['destination_ip'];remote=e.get('source_ip');break
  lease=self.leases.get(client,{}) if client else {};identity=self.identities.get(client,{}) if client else {}
  e.update(client_ip=client,remote_ip=remote,client_name=lease.get('hostname'),client_mac=lease.get('mac'),client_label=identity.get('identity_label') or lease.get('hostname') or client or 'Unattributed',device_type=identity.get('device_type'),device_type_confidence=identity.get('device_type_confidence'),device_vendor=identity.get('mac_vendor'),device_mac_kind=identity.get('mac_kind'),remote_port=e.get('destination_port'))
  bypass=dns_bypass_sensor.classify_event(e,local_dns_addresses=self.local_dns,configured_upstreams=self.upstreams)
  if bypass:e['dns_bypass_indicator']=bypass
  return e
 def _worker(self,iface,sock):
  while not self.stop_event.is_set():
   try:data,anc,flags,addr=sock.recvmsg(65535,256)
   except socket.timeout:continue
   except OSError as ex:
    if not self.stop_event.is_set():self.errors.append(f'{iface}: {ex}'[:180])
    break
   epoch=time.time_ns()
   for level,kind,cmsg in anc:
    if level==socket.SOL_SOCKET and kind==getattr(socket,'SO_TIMESTAMPNS',35) and len(cmsg)>=16:
     sec,nsec=struct.unpack('=qq',cmsg[:16]);epoch=sec*1_000_000_000+nsec;break
   ptype=addr[2] if len(addr)>2 and isinstance(addr[2],int) else 0;link=addr[1] if len(addr)>1 and isinstance(addr[1],int) else None
   e=self._event(iface,ptype,link,data,epoch);self.last_packet_at=epoch/1e9
   client_ip=e.get('client_ip');source_ip=e.get('source_ip');destination_ip=e.get('destination_ip')
   if client_ip and source_ip==client_ip:
    direction='upload';client_port=e.get('source_port');remote_port=e.get('destination_port')
   elif client_ip and destination_ip==client_ip:
    direction='download';client_port=e.get('destination_port');remote_port=e.get('source_port')
   else:
    direction='unknown';client_port=e.get('source_port');remote_port=e.get('destination_port')
   flow_client=client_ip or source_ip;flow_remote=e.get('remote_ip') or destination_ip
   flow_id=self.flow_tracker.record(packet_bytes=len(data),packet_timestamp_ns=epoch,direction=direction,metadata={'interface':iface,'client_ip':flow_client,'remote_ip':flow_remote,'client_port':client_port,'remote_port':remote_port,'protocol':e.get('protocol'),'application':e.get('application')})
   e['flow_id']=flow_id
   now_mono=time.monotonic();last_emit=self.flow_event_emit.get(flow_id,0.0)
   if e.get('application') in ('DNS','DHCP','ARP','mDNS','SSDP / UPnP') or now_mono-last_emit>=1.0:
    self.next_id+=1;e['id']=self.next_id;self.events.append(e);self.flow_event_emit[flow_id]=now_mono;self.flow_event_emit.move_to_end(flow_id)
    while len(self.flow_event_emit)>MAX_FLOWS:self.flow_event_emit.popitem(last=False)
    if len(self.events)==self.events.maxlen:self.overwritten+=1
   c=self.counts[iface];c['packets']+=1;c['bytes']+=len(data)
   if self.writer:self.writer.write_packet(iface,data,epoch)
  try:
   raw=sock.getsockopt(SOL_PACKET,PACKET_STATISTICS,8);received,dropped=struct.unpack('=II',raw[:8]);self.counts[iface]['kernel_packets']+=received;self.counts[iface]['socket_drops']+=dropped
  except OSError:pass
  try:sock.close()
  except OSError:pass
 def start(self,duration_seconds,interfaces,allowed_interfaces=None,subnets=(),save_pcap=False,scope_networks=None,ap_dns_addresses=None,configured_upstreams=None):
  if os.geteuid()!=0:raise PermissionError('Packet capture requires privileged agent.')
  if isinstance(duration_seconds,bool) or not isinstance(duration_seconds,int) or not 10<=duration_seconds<=MAX_CAPTURE_SECONDS:raise ValueError('Capture duration must be 10 to 600 seconds.')
  if not isinstance(allowed_interfaces,dict) or not allowed_interfaces:raise ValueError('Configured capture interface allowlist required.')
  if not isinstance(interfaces,list) or not 1<=len(interfaces)<=4 or len(set(interfaces))!=len(interfaces) or any(x not in allowed_interfaces for x in interfaces):raise ValueError('Capture interface outside allowlist.')
  if save_pcap and duration_seconds>300:raise ValueError('PCAPNG duration limited to 300 seconds.')
  self.stop()
  opened=[]
  try:
   for iface in interfaces:
    sock=socket.socket(socket.AF_PACKET,socket.SOCK_DGRAM,socket.htons(ETH_P_ALL));sock.setsockopt(socket.SOL_SOCKET,socket.SO_RCVBUF,4*1024*1024)
    try:sock.setsockopt(socket.SOL_SOCKET,getattr(socket,'SO_TIMESTAMPNS',35),1)
    except OSError:pass
    sock.settimeout(.25);sock.bind((iface,0));opened.append((iface,sock))
   self.writer=PcapngWriter(interfaces) if save_pcap else None
  except OSError as e:
   for _,x in opened:x.close()
   raise RuntimeError(f'Could not start packet capture: {e}')
  self.events.clear();self.flow_tracker.reset();self.flow_event_emit.clear();self.next_id=0;self.overwritten=0;self.errors=[];self.counts={i:{'packets':0,'bytes':0,'kernel_packets':0,'socket_drops':0,'socket_rcvbuf_bytes':s.getsockopt(socket.SOL_SOCKET,socket.SO_RCVBUF)} for i,s in opened}
  self.interfaces=list(interfaces);self.allowed=dict(allowed_interfaces);self.subnets=tuple(subnets);self.scope=dict(scope_networks or {});self.local_dns=set(ap_dns_addresses or ());self.upstreams=set(configured_upstreams or ())
  self.started=time.time();self.duration=duration_seconds;self.stop_at=self.started+duration_seconds;self.last_packet_at=None;self.active=True;self.stop_event=threading.Event();self.sockets=[x for _,x in opened];self._refresh_maps()
  self.threads=[]
  for iface,sock in opened:
   t=threading.Thread(target=self._worker,args=(iface,sock),daemon=True,name='packet-'+iface);t.start();self.threads.append(t)
  sampler=threading.Thread(target=self._flow_sampler_worker,daemon=True,name='flow-rate-sampler');sampler.start();self.threads.append(sampler)
  timer=threading.Thread(target=self._expiry,daemon=True);timer.start();self.threads.append(timer)
  return self.snapshot(0,0)
 def _flow_sampler_worker(self):
  deadline=time.monotonic()+1.0
  while not self.stop_event.is_set():
   if self.stop_event.wait(max(0.0,deadline-time.monotonic())):break
   try:self.flow_tracker.sample_once()
   except Exception as ex:self.errors.append(f'flow sampler: {ex}'[:180])
   now=time.monotonic();deadline+=1.0
   if now>deadline:deadline=now+1.0
 def _expiry(self):
  while not self.stop_event.wait(.5):
   if time.time()>=self.stop_at:self.stop();return
 def stop(self):
  was=self.active;self.active=False;self.stop_event.set()
  # Let recvmsg time out naturally so PACKET_STATISTICS can be read before
  # the socket is closed. Then force-close only any worker that did not exit.
  for t in self.threads:
   if t is not threading.current_thread():t.join(.6)
  for sock in self.sockets:
   try:sock.close()
   except OSError:pass
  for t in self.threads:
   if t is not threading.current_thread() and t.is_alive():t.join(.3)
  self.sockets=[];self.threads=[]
  if was:
   try:self.flow_tracker.sample_once()
   except Exception as ex:self.errors.append(f'final flow sample: {ex}'[:180])
  if self.writer:self.writer.close();self.last_pcap=self.writer.path.name;self.last_pcap_bytes=self.writer.size;self.writer=None
  return {'ok':True,'stopped':was,'capture':self.snapshot(0,0)['capture']}
 def snapshot(self,after=0,limit=200):
  if isinstance(after,bool) or not isinstance(after,int) or after<0:after=0
  if isinstance(limit,bool) or not isinstance(limit,int) or not 0<=limit<=250:limit=200
  events=[dict(x) for x in self.events if x['id']>after][:limit] if limit else []
  flows=self.flow_tracker.summary(100);flow_status=self.flow_tracker.status()
  capture={'active':self.active,'started_at':self.started,'stop_at':self.stop_at,'duration_seconds':self.duration,'interfaces':self.interfaces,'counts':{k:dict(v) for k,v in self.counts.items()},'errors':self.errors[-8:],'ring_capacity':self.events.maxlen,'ring_size':len(self.events),'overwritten_events':self.overwritten,'last_packet_at':self.last_packet_at,'last_event_id':self.next_id,'flow_count':flow_status['active_flows'],'flows':flows,'flow_sampling':flow_status,'mode':'bounded metadata + optional PCAPNG','payload_retained_in_memory':False,'pcapng_enabled':bool(self.writer),'pcapng_path':str(self.writer.path) if self.writer else str(CAPTURE_DIR/self.last_pcap) if self.last_pcap else None,'pcapng_bytes':self.writer.size if self.writer else self.last_pcap_bytes,'pcapng_limit_reached':bool(self.writer and self.writer.full),'conntrack_available':self.conntrack_path.exists()}
  return {'ok':True,'capture':capture,'events':events,'flows':flows}
 def flow_series(self,flow_id,limit=60):return self.flow_tracker.series(flow_id,limit)
def adapter_inventory(interfaces=None):return wireless_adapter.status(tuple((interfaces or {}).keys())).get('adapters',[])
