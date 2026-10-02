#!/usr/bin/env python3
"""Packet-level connection summaries. Requires scapy; no network access.

Usage: python3 diagnostics/analyze.py ARTIFACT_DIRECTORY > analysis.jsonl
SLL2 captures include both eth0 and its Azure VF: retain eth0 (ifindex 2).
Capture lengths >1500 with offloads enabled are NOT wire packet lengths.
"""
import collections
import json
import pathlib
import sys
from scapy.all import rdpcap, IP, TCP, ICMP, CookedLinuxV2

root = pathlib.Path(sys.argv[1])
packets = rdpcap(str(root / "ia.pcap"))
labels = {}
for path in root.rglob("*.jsonl"):
    for line in path.read_text().splitlines():
        try:
            r = json.loads(line)
        except ValueError:
            continue
        if "local" in r:
            labels[int(r["local"].rsplit(":", 1)[1])] = {"file": str(path.relative_to(root)), **r}

flows = collections.defaultdict(list)
icmp = collections.Counter()
for p in packets:
    if CookedLinuxV2 in p and p[CookedLinuxV2].ifindex != 2:
        continue
    if ICMP in p:
        icmp[(p[ICMP].type, p[ICMP].code)] += 1
    if IP not in p or TCP not in p:
        continue
    t = p[TCP]
    if t.dport == 443:
        flows[t.sport].append(p)
    elif t.sport == 443:
        flows[t.dport].append(p)

for port, ps in flows.items():
    syn = next((p for p in ps if p[TCP].sport == port and p[TCP].flags == "S"), None)
    if syn is None:
        continue
    base = syn[TCP].seq
    sent = [p for p in ps if p[TCP].sport == port and bytes(p[TCP].payload)]
    received = [p for p in ps if p[TCP].dport == port]
    sack = sorted(set(tuple((n - base) % 2**32 for n in v)
                      for p in received for k, v in p[TCP].options if k == "SAck"))
    acks = [(p[TCP].ack - base) % 2**32 for p in received if p[TCP].flags.A]
    first = sent[0] if sent else None
    r = {
        "port": port,
        "label": labels.get(port),
        "syn_mss": dict(syn[TCP].options).get("MSS"),
        "first_data_ip_length": first[IP].len if first else None,
        "first_data_df": bool(first[IP].flags.DF) if first else None,
        "first_data_payload_length": len(bytes(first[TCP].payload)) if first else None,
        "sent_ip_lengths": dict(collections.Counter(p[IP].len for p in sent)),
        "max_ack_relative": max(acks, default=0),
        "sack_ranges_relative": sack,
        "received_payload_bytes_in_capture": sum(len(bytes(p[TCP].payload)) for p in received),
    }
    print(json.dumps(r))
print(json.dumps({"icmp_type_code_counts": {str(k): v for k, v in icmp.items()}}))
