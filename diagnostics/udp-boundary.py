#!/usr/bin/env python3
"""Conventional TTL probing with a fixed UDP tuple and paired IP lengths.
No service data; destination is a high traceroute port. 48 packets by default.
"""
import argparse,json,socket,time
from scapy.all import IP,UDP,ICMP,Raw,send,AsyncSniffer,conf
p=argparse.ArgumentParser();p.add_argument('--iface',required=True);p.add_argument('--ip',default='145.116.0.213');a=p.parse_args();conf.verb=0
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.connect((a.ip,33434));local,port=s.getsockname()
def emit(d):print(json.dumps(d),flush=True)
def recv(pkt):
 if ICMP not in pkt or pkt[ICMP].type not in (3,11):return
 q=pkt[ICMP].payload
 try:emit(dict(kind='icmp',time=time.time(),router=pkt[IP].src,type=int(pkt[ICMP].type),code=int(pkt[ICMP].code),quote_len=int(q.len),quote_ttl=int(q.ttl),quote_port=int(q.payload.sport),quote_id=int(q.id),mtu=int(pkt[ICMP].nexthopmtu or 0)))
 except (AttributeError,TypeError,ValueError):emit(dict(kind='unparsed',summary=pkt.summary()))
sn=AsyncSniffer(iface=a.iface,filter='icmp',prn=recv,store=False);sn.start();time.sleep(.3)
try:
 for df in (True,False):
  for ttl in range(18,30):
   for size in ([1490,1491] if df else [1491,1490]):
    ip=IP(src=local,dst=a.ip,id=32001 if df else 32002,ttl=ttl,flags='DF' if df else 0)
    pkt=ip/UDP(sport=port,dport=33434)/Raw(b'p'*(size-28));assert len(bytes(pkt))==size
    emit(dict(kind='send',time=time.time(),port=port,ttl=ttl,size=size,df=df))
    send(pkt,verbose=False);time.sleep(.45)
finally:time.sleep(.3);sn.stop();s.close()
