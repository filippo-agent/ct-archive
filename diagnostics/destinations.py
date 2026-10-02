#!/usr/bin/env python3
import argparse,json,socket,time,struct,sys
p=argparse.ArgumentParser();p.add_argument("--hosts",default="dn760103.eu.archive.org,ia801402.us.archive.org,archive.org,proxy.golang.org,www.google.com,example.com,github.com,azure-sweet.exe.xyz");p.add_argument("--sizes",default="307,1438,1439,1448,2048");p.add_argument("--filter",action="store_true");p.add_argument("--targets-file");p.add_argument("--resolve",action="store_true");a=p.parse_args()
hosts=a.hosts.split(",")
targets=[]
for host in (hosts if not a.targets_file or a.resolve else []):
 try: ip=socket.gethostbyname(host);targets.append((host,ip))
 except OSError as e:print(json.dumps(dict(kind='dns-error',host=host,error=str(e))),flush=True)
if a.targets_file:
 if a.resolve:json.dump(targets,open(a.targets_file,"w"))
 else:targets=json.load(open(a.targets_file))
if a.filter:
 print('tcp port 443 and ('+' or '.join('host '+ip for _,ip in targets)+')');sys.exit()
print(json.dumps(dict(kind='targets',targets=targets)),flush=True)
for host,ip in targets:
 for n in map(int,a.sizes.split(",")):
  s=socket.socket();s.settimeout(2);s.setsockopt(socket.IPPROTO_TCP,socket.TCP_NODELAY,1)
  start=time.time();r=dict(host=host,ip=ip,size=n,start=start)
  try:
   s.connect((ip,443));r['local']=s.getsockname();r['tcp_ms']=int((time.time()-start)*1000)
   pre=f'GET / HTTP/1.1\r\nHost: {host}\r\nX-Probe: '.encode();end=b'\r\nConnection: close\r\n\r\n';data=pre+b'a'*(n-len(pre)-len(end))+end
   s.sendall(data);r['response']=s.recv(4096)[:120].decode('ascii',errors='replace')
  except OSError as e:r['error']=str(e)
  finally:
   s.setsockopt(socket.SOL_SOCKET,socket.SO_LINGER,struct.pack('ii',1,0));s.close()
  r['elapsed_ms']=int((time.time()-start)*1000);print(json.dumps(r),flush=True);time.sleep(.1)
