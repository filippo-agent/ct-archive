# Why `GODEBUG=tlsmlkem=0` fixes the observed IA/GitHub Actions TLS stalls

**Investigation: October 2, 2026.**
Separate Shelley conversation `c32NRPP`. Work was isolated in
`/tmp/ct-archive-network-probe`, on the agent-owned fork branch
`diagnose-ia-tls-packets`. No main-PR code was changed, no external issue was
filed, and no humans were contacted.

## Bottom line

**The reproduced immediate cause is loss of large outbound TCP/IP packets,
not ML-KEM negotiation.** Default Go's larger ClientHello exposes the loss;
`tlsmlkem=0` avoids it by reducing the first flight's size.

The final affected runner delivered **1490-byte IPv4 packets**, but not
**1491-byte packets**. Removing TCP timestamp options preserved that IP-size
cutoff while shifting the TCP-payload boundary by exactly 12 bytes.

This establishes an **IP-size-sensitive outbound TCP delivery black hole**.
It does **not** identify the dropping component, establish a particular
router's MTU, or distinguish an MTU/tunnel/frame-size defect from a packet-size
filter. Clearing DF did not repair the oversized failures, so calling it
definitively “a router with MTU=1490 and blocked ICMP” would overstate the
evidence.

## Exact causal chain, with packet evidence

1. Go 1.25.4 with the probe's HTTP-equivalent ALPN sends a **1529-byte initial
   TLS record**, including the five-byte record header. It advertises group
   `0x11ec` and sends a 1216-byte X25519MLKEM768 key share, plus the 32-byte
   X25519 fallback share.
2. With `tlsmlkem=0`, that record is **307 bytes**. The 1222-byte difference is
   the 1220-byte hybrid KeyShareEntry (1216 data + four framing bytes) and the
   two-byte supported-group identifier. Captured ClientHellos and the
   official Go 1.25.4 source agree on this.
3. The default TCP connection advertises MSS1460 and negotiates timestamps.
   Full-sized segments have 1448 payload bytes + 20 IPv4 + 32 TCP = **1500 IP
   bytes**. The default first flight therefore entails a 1448-byte prefix and
   an 81-byte tail.
4. In the failure, the peer cumulatively ACKs only the SYN (relative ACK=1),
   but SACKs relative bytes **`[1449,1530)`**: precisely the final 81 bytes.
   The prefix is absent. The client retransmits that 1448-byte prefix in
   1500-byte IP packets, without progress. No TLS bytes are read.
5. Consequently the peer cannot reconstruct even the first TLS record.
   There is no ServerHello, HelloRetryRequest, or TLS alert in those failed
   connections. The application eventually reports its TLS-handshake timeout.
6. The smaller classical ClientHello fits in a small packet and gets delivered.
   The peer then completes the TLS handshake. This is why the environment
   toggle works on these paths.

First-stage extract:
`diagnostics/fixtures/default-vs-mss900.pcap`, source ports 47790 and 50622,
from run 37052167770 / job 110987969365. Full captures also record the repeated
prefix transmissions and the peer's later timeout close.

## Controls that discriminate competing explanations

All variants within a job used fresh connections, one pinned IPv4 address
(`145.116.0.213`), and the same SNI (`dn760103.eu.archive.org`). Trials were
interleaved and repeated in reverse order.

| Control | Observation | What it establishes |
|---|---|---|
| Default versus classical Go, first-stage two runners / two rounds | Default 4/4 failed; classical 4/4 completed | Reproduces the workaround in controlled jobs |
| Classical-only ClientHello padded to 1529 bytes | 4/4 failed with missing-prefix / SACKed-tail behavior | No hybrid group/keyshare is necessary to trigger the loss |
| Unmodified default TLS with TCP_MAXSEG=900 | 4/4 completed verified TLS 1.3, selecting X25519MLKEM768 | The endpoint can negotiate ML-KEM on the very runners whose ordinary default handshake fails |
| Unmodified default TLS, first write divided into 512-byte TCP writes | Completed with X25519MLKEM768, normal negotiated MSS retained | Fixing only outbound packetization suffices; smaller inbound MSS is not required |
| ClientHello divided into 512-byte TLS-record bodies, records written together | Failed; TCP still emitted full-sized packets | TLS-record splitting alone is not a fix; not evidence of record-fragmentation intolerance |
| Small CH still advertising ML-KEM, but omitting its key share | Received HRR selecting `0x11ec` | The peer recognizes and requests the hybrid group |
| Plaintext HTTP to the HTTPS port, in Go and then Python | Small requests received nginx's expected 400; larger ones were not TCP-ACKed | TLS, ML-KEM, and Go are unnecessary for the underlying delivery failure |
| TSO/GSO/GRO disabled on eth0 and its Azure VF | Failure persisted; segmented sends visible in captures | Loss is not merely a misleading offload capture artifact |
| Timestamp-enabled Python payload 1438 versus 1439 bytes | IP1490 delivered and ACKed; IP1491 repeatedly unACKed, in both orders | Sharp packet-size cutoff |
| Timestamps disabled: payload 1450 versus 1451 bytes | IP1490 delivered; IP1491 unACKed, in both orders | Cutoff tracks IP length, not TLS layout, TCP payload length, or the timestamp option itself |
| DF cleared per socket | Actual DF-clear 1492/1500-byte sends still failed; a larger write again had its tail SACKed | Clearing DF did not repair it; not a silent reduction of TCP MSS |

All successful ML-KEM handshakes used normal certificate verification. The
observed leaf issuer was Let's Encrypt YE1, with the expected hostname. No
`InsecureSkipVerify`, TLS-version cap, or special cipher selection was used.

Raw externally mutated TLS first flights were used only to inspect TCP
delivery / the first server record, not claimed to complete a handshake:
external mutation changes Go's stored handshake transcript. The complete
successful handshakes used unmodified ClientHello handshake bytes.

## Smallest reproducers obtained

### TLS alone, on an affected GitHub runner

`diagnostics/minimal.go` does only a verified `tls.DialWithDialer` to the pinned
IP with the IA ServerName. No HTTP, ALPN, redirects, parallel requests, or
torrent downloads are needed.

```sh
go build -o /tmp/ia-minimal diagnostics/minimal.go
GODEBUG= /tmp/ia-minimal
GODEBUG=tlsmlkem=0 /tmp/ia-minimal
```

On **the same runner**, Go 1.25.4 and Go 1.27.1 both failed the default
handshake at the five-second deadline. Their identical binaries with
`tlsmlkem=0` completed in about 0.28 seconds. The corresponding minimal
default ClientHello records are 1511 and 1527 bytes, respectively; both
still expose the full-sized first-packet loss.

### No TLS and no Go

```sh
python3 diagnostics/tcp-repro.py --sizes 1438,1439 --rounds 2
```

It sends one valid plaintext HTTP request, padded to the requested size, to
port443. On the measured timestamp-enabled runner, 1438-byte payloads work,
1439-byte payloads fail. Expect a 400 response in the successful case; it is
the deliberately expected response to HTTP on a HTTPS port.

Recheck DNS before reusing the fixed address. A different runner/path may
succeed. This VM itself successfully completed a default Go 1.27.1 handshake
selecting ML-KEM, consistent with the known intermittent upstream successes.

## Runs and preserved evidence

Four bounded workflows used six runner jobs. They sent only TLS handshakes,
small public plaintext diagnostic requests, and bounded ICMP echoes; no
torrent or ZIP bodies were downloaded.

| Run | Source commit | Regions | Artifacts |
|---|---|---|---|
| https://github.com/filippo-agent/ct-archive/actions/runs/37052167770 | `98aaf93` | westus3, westus | `ia-tls-1`, `ia-tls-2` |
| https://github.com/filippo-agent/ct-archive/actions/runs/37052773599 | `f2862ff` | westus3, centralus | `ia-tls-1`, `ia-tls-2` |
| https://github.com/filippo-agent/ct-archive/actions/runs/37053272396 | `0d99ae6` | westus3 | `ia-tls-minimal` |
| https://github.com/filippo-agent/ct-archive/actions/runs/37053716621 | `d85ac86` | westus3 | `ia-df-control` |

Complete source, workflow snapshots, reproducers, and two small permanent
PCAP extracts are in:

https://github.com/filippo-agent/ct-archive/tree/diagnose-ia-tls-packets/diagnostics

GitHub artifacts have 14-day retention. Full durable VM copies are under:

```
/home/exedev/ia-tls-artifacts/run-<RUN_ID>/
```

Each contains the Actions log, filtered full PCAP, per-trial result logs,
environment/segmentation-offload state, and generated `analysis.jsonl`
summaries. First-stage and second-stage artifacts additionally contain
application-side read/write traces, raw ClientHellos/first replies and
public-handshake TLS key logs.

The permanent `fixtures/ip1490-vs-ip1491.pcap` contains the timestamp-enabled
and timestamp-free cutoff pairs, plus a DF-clear failure. Fixture hashes are
in `fixtures/SHA256SUMS`.

`diagnostics/analyze.py` requires scapy and correlates source ports with
trial labels, IP sizes, DF flags, and relative ACK/SACK ranges. Captures use
Linux SLL2. With `-i any`, eth0 and the Azure VF duplicate many packets;
the analyzer and extracts retain only eth0 (ifindex2). Offload-enabled
super-packets are explicitly not interpreted as on-wire packet lengths.
The cutoff tests disabled TSO/GSO/GRO.

Copies of the official Go 1.25.4 `defaults.go` / `handshake_client.go` source
and RFC2923 are also saved under `/home/exedev/ia-tls-artifacts/`.

## Remaining uncertainty and limits

* No server-side or intermediate-hop packet capture exists. The drop could
  be at runner egress, transit, IA ingress, a tunnel, a frame-size-limited
  component, or a size filter before the peer TCP stack. The captures
  establish the client-visible size-sensitive loss, not its owner.
* No fragmentation-needed ICMP reached the runner in the size experiments.
  Absence does not establish where it was suppressed or whether any router
  generated it. DF-clear packets also failed.
* ICMP echo failed for every tested size, including an 84-byte IP packet;
  therefore the larger echo failures do not independently measure PMTU.
* The reason for historical default-Go successes remains unmeasured.
  Upstream run 37050840319 succeeded in eastus2 and 37047727979 in
  northcentralus; run 37050014869 failed in eastus. Thus region alone is not
  an established predictor. Earlier successes did not have packet captures.
* There is no basis for a blanket IA ML-KEM incompatibility claim, an
  automatic Go retry/fallback recommendation, or a Go crypto/tls code fix.
  The endpoint's verified ML-KEM completions on affected runners directly
  contradict the generic server-incompatibility explanation.
* Further localization would need additional controlled destinations/ports,
  paired affected/unaffected paths, or network-owner/IA-side observations.
  None of those requires weakening the application further; contacting
  owners or filing an issue remains subject to the user's permission.
