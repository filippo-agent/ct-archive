import json,sys,pathlib
from scapy.all import rdpcap,IP,TCP,Raw
root=pathlib.Path(sys.argv[1]); packets=rdpcap(str(root/'ia.pcap'))
for r in map(json.loads,(root/'results.jsonl').read_text().splitlines()):
 port=int(r['local'].split(':')[-1]);ps=[p for p in packets if TCP in p and (p[TCP].sport==port or p[TCP].dport==port)];cseq=sseq=None
 print('\n',r['name'],'ERR',r.get('error','OK'))
 for p in ps:
  t=p[TCP];client=t.sport==port
  if client and cseq is None:cseq=t.seq
  if not client and sseq is None:sseq=t.seq
  seqbase=cseq if client else sseq; ackbase=sseq if client else cseq
  print(f'{float(p.time-ps[0].time):7.3f}', 'C>S' if client else 'S>C','IPLEN',p[IP].len,'flags',str(t.flags),'seq',t.seq-seqbase,'ack',t.ack-ackbase if ackbase is not None and t.ack else '-', 'payload',len(bytes(t.payload)),'opts',t.options)
