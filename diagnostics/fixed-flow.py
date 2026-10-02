#!/usr/bin/env python3
"""Same-five-tuple TTL/size control. Only sends bounded incomplete HTTP requests
on connections opened by this process. No third-party source spoofing.
Scapy handles Darwin raw socket framing; original pcaps are authoritative.
"""
import argparse,json,socket,struct,time
from scapy.all import IP,TCP,ICMP,Raw,AsyncSniffer,send,conf
p=argparse.ArgumentParser();p.add_argument('--iface',required=True);p.add_argument('--ip',default='145.116.0.213');p.add_argument('--first-ttl',type=int,default=14);p.add_argument('--last-ttl',type=int,default=25);p.add_argument('--flows',type=int,default=3);a=p.parse_args();conf.verb=0

def emit(x):print(json.dumps(x),flush=True)
for flow in range(a.flows):
 c=socket.socket();c.settimeout(4);c.bind(('',0));port=c.getsockname()[1]
 sn=AsyncSniffer(iface=a.iface,filter=f'tcp and host {a.ip} and port {port}',store=True);sn.start();time.sleep(.2)
 c.connect((a.ip,443));local=c.getsockname()[0];time.sleep(.2);pkts=sn.stop()
 syn=next(x for x in pkts if TCP in x and x[IP].src==local and x[TCP].flags & 2)
 sa=next(x for x in pkts if TCP in x and x[IP].src==a.ip and x[TCP].flags & 2)
 ack=next(x for x in reversed(pkts) if TCP in x and x[IP].src==local and int(x[TCP].flags)==16)
 seq=int(syn[TCP].seq)+1;ackseq=int(sa[TCP].seq)+1
 opts=ack[TCP].options
 header=TCP(sport=port,dport=443,flags='PA',seq=seq,ack=ackseq,window=65535,options=opts)
 hlen=len(bytes(header));base=IP(src=local,dst=a.ip,flags='DF',id=31000+flow)
 emit(dict(kind='flow',flow=flow,src=local,port=port,seq=seq,ack=ackseq,opts=opts,header_bytes=hlen))
 # Capture ICMP asynchronously while leaving the real connected socket idle.
 def callback(pkt):
  if ICMP not in pkt or pkt[ICMP].type not in (3,11):return
  q=pkt[ICMP].payload
  # Scapy decodes IPerror/TCPerror as subclasses; fields are network-correct.
  try:
   emit(dict(kind='icmp',flow=flow,time=time.time(),router=pkt[IP].src,type=int(pkt[ICMP].type),code=int(pkt[ICMP].code),quote_src=q.src,quote_dst=q.dst,quote_len=int(q.len),quote_ttl=int(q.ttl),quote_port=int(q.payload.sport),quote_seq=int(q.payload.seq)))
  except (AttributeError,TypeError,ValueError):emit(dict(kind='icmp-unparsed',summary=pkt.summary()))
 rs=AsyncSniffer(iface=a.iface,filter='icmp',prn=callback,store=False);rs.start();time.sleep(.15)
 try:
  for ttl in range(a.first_ttl,a.last_ttl+1):
   # Alternate size order across flows to avoid a fixed order/rate-limit bias.
   for size in ([1490,1491] if flow%2==0 else [1491,1490]):
    n=size-20-hlen
    prefix=b'GET / HTTP/1.1\r\nHost: dn760103.eu.archive.org\r\nX-Probe: '
    payload=prefix+b'a'*(n-len(prefix)) # intentionally unfinished header
    pkt=base.copy();pkt.ttl=ttl;pkt=pkt/header/Raw(payload)
    assert len(bytes(pkt))==size
    emit(dict(kind='send',flow=flow,port=port,time=time.time(),ttl=ttl,ip_len=size))
    send(pkt,iface=a.iface,verbose=False);time.sleep(.35)
 finally:
  time.sleep(.2);rs.stop()
  try:c.setsockopt(socket.SOL_SOCKET,socket.SO_LINGER,struct.pack('ii',1,0))
  except OSError:pass
  c.close()
  for n in (1490-20-hlen,1491-20-hlen):send(IP(src=local,dst=a.ip)/TCP(sport=port,dport=443,seq=seq+n,ack=ackseq,flags='R'),verbose=False)
 time.sleep(.2)
