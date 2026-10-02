#!/usr/bin/env python3
import json,socket,time,struct,sys
hosts=['dn760103.eu.archive.org','ia801402.us.archive.org','archive.org','proxy.golang.org','www.google.com','example.com','github.com','azure-sweet.exe.xyz']
targets=[]
for host in hosts:
 try: ip=socket.gethostbyname(host);targets.append((host,ip))
 except OSError as e:print(json.dumps(dict(kind='dns-error',host=host,error=str(e))),flush=True)
if '--filter' in sys.argv:
 print('tcp port 443 and ('+' or '.join('host '+ip for _,ip in targets)+')');sys.exit()
print(json.dumps(dict(kind='targets',targets=targets)),flush=True)
for host,ip in targets:
 for n in [307,1438,1439,1448,2048]:
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
