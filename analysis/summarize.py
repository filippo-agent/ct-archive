#!/usr/bin/env python3
"""Summarize per-probe TCP delivery using original logs to map local ports.
Capture records are not assumed to be wire packets when offloads are enabled.
"""
import csv, io, re, subprocess, sys
from pathlib import Path
pcap, *logs = sys.argv[1:]
fields=['frame.number','frame.time_relative','ip.src','ip.len','tcp.srcport','tcp.dstport','tcp.seq','tcp.ack','tcp.len','tcp.options.sack_le','tcp.options.sack_re','tls.handshake.extensions_key_share_group']
out=subprocess.check_output(['tshark','-r',pcap,'-T','fields','-E','separator=\t',*[v for f in fields for v in ['-e',f]]],text=True)
rows=list(csv.reader(io.StringIO(out),delimiter='\t'))
print('log\tprobe\tport\tmax_sent_ip_len\tmax_peer_ack\tpeer_sacks\tserver_groups')
for log in logs:
 for line in Path(log).read_text().splitlines():
  m=re.match(r'(\S+) start=\S+ local=([\d.]+):(\d+) remote=',line)
  if not m:continue
  name,ip,port=m.groups();r=[x for x in rows if x[4]==port or x[5]==port]
  sent=[x for x in r if x[2]==ip and int(x[8] or '0')>0]
  recv=[x for x in r if x[2]!=ip]
  sacks=sorted({x[9]+':'+x[10] for x in recv if x[9]})
  groups=sorted({x[11] for x in recv if x[11]})
  print(f'{Path(log).name}\t{name}\t{port}\t{max([int(x[3]) for x in sent],default=0)}\t{max([int(x[7] or 0) for x in recv],default=0)}\t{",".join(sacks)}\t{",".join(groups)}')
