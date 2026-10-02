#!/usr/bin/env python3
"""Bounded TTL/size probe using established TCP sockets and public HTTP bytes.
ICMP quotes are joined to socket ports; pcap remains the authority for wire sizes.
Run as root only for the ICMP listener. No raw packet injection.
"""
import argparse, json, socket, struct, threading, time
p=argparse.ArgumentParser();p.add_argument('--ip',default='145.116.0.213');p.add_argument('--host',default='dn760103.eu.archive.org');p.add_argument('--max-ttl',type=int,default=28);p.add_argument('--wait',type=float,default=.65);a=p.parse_args()
lock=threading.Lock();labels={};stop=False

def emit(d):
 with lock: print(json.dumps(d),flush=True)

def listener():
 s=socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.IPPROTO_ICMP);s.settimeout(.2)
 while not stop:
  try:b,_=s.recvfrom(65535)
  except socket.timeout:continue
  now=time.time();hl=(b[0]&15)*4;i=b[hl:];typ,code=i[:2]
  if typ not in (3,11) or len(i)<36:continue
  q=i[8:];ql=(q[0]&15)*4
  if q[9]!=6 or len(q)<ql+8:continue
  dest=socket.inet_ntoa(q[16:20]);sport,dport=struct.unpack('!HH',q[ql:ql+4])
  if dest!=a.ip:continue
  emit(dict(kind='icmp',time=now,router=socket.inet_ntoa(b[12:16]),type=typ,code=code,mtu=struct.unpack('!H',i[6:8])[0] if typ==3 and code==4 else None,quoted_ip_len=struct.unpack('!H',q[2:4])[0],quoted_ttl=q[8],sport=sport,dport=dport,probe=labels.get(sport)))
 s.close()
t=threading.Thread(target=listener);t.start()

def probe(ttl,n,port=443,df=True):
 label=dict(ttl=ttl,bytes=n,port=port,df=df)
 s=socket.socket();s.settimeout(3);s.setsockopt(socket.IPPROTO_TCP,socket.TCP_NODELAY,1)
 # DONT (DF=0) or PROBE (DF=1, ignore a cached path MTU).
 s.setsockopt(socket.IPPROTO_IP,10,3 if df else 0)
 start=time.time()
 try:
  s.connect((a.ip,port));addr=s.getsockname();labels[addr[1]]=label
  s.setsockopt(socket.IPPROTO_IP,socket.IP_TTL,ttl)
  prefix=f'GET / HTTP/1.1\r\nHost: {a.host}\r\nX-Pad: '.encode();suffix=b'\r\nConnection: close\r\n\r\n'
  payload=prefix+b'a'*(n-len(prefix)-len(suffix))+suffix
  assert len(payload)==n
  s.settimeout(a.wait);s.sendall(payload)
  try:result=s.recv(4096);response=result[:90].decode('ascii',errors='replace');err=None
  except OSError as e:response=None;err=str(e)
  emit(dict(kind='result',start=start,elapsed=time.time()-start,local=addr,probe=label,response=response,error=err))
 except OSError as e:emit(dict(kind='connect-error',probe=label,error=str(e)))
 finally:
  s.setsockopt(socket.IPPROTO_IP,socket.IP_TTL,64);s.setsockopt(socket.SOL_SOCKET,socket.SO_LINGER,struct.pack('ii',1,0));s.close()
 time.sleep(.08)
try:
 # Size/DF/port controls before tracing, all on the same runner.
 for port in (443,80):
  for df in (True,False):
   for n in (307,1438,1448):probe(64,n,port,df)
 for ttl in range(1,a.max_ttl+1):
  for n in (307,1448):probe(ttl,n)
finally:
 stop=True;t.join()
