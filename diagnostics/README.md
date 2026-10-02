# Internet Archive / GitHub Actions TLS investigation

Investigation date: **October 2, 2026**. This orphan diagnostic branch does not
contain or run the archive linter. The application PR was not modified.

## Result

The reproduced failure is an **outbound IP-size-sensitive TCP delivery black
hole**, not an ML-KEM negotiation failure. In the final controlled runner,
1490-byte IPv4 packets arrived and 1491-byte packets did not. The boundary was
unchanged when TCP timestamp options were removed. Clearing DF did not repair
the tested oversized-packet failures (1492 and 1500 bytes).

Go's default ML-KEM ClientHello exposes this by causing a full-sized 1500-byte
IP packet. `tlsmlkem=0` makes the ClientHello small enough to avoid it.
The endpoint successfully completed verified TLS 1.3 / X25519MLKEM768
handshakes when only TCP MSS or the sizes of TCP writes were changed.

**Do not infer that a particular router has MTU=1490.** Clearing DF did not fix
the loss, and no fragmentation-needed ICMP reached the runner. The observations
establish size-sensitive delivery loss; an MTU/tunnel defect versus a packet-size
filter, and the location/owner of the dropping component, remain unresolved.

## Reproducers

Check DNS before reusing the pinned IP: it was `145.116.0.213` on the investigation
date. Affected GitHub-hosted Ubuntu runners reproduce this; the exe.dev VM did
not. A successful run on another path is not a disproof.

```sh
go build -o /tmp/ia-minimal diagnostics/minimal.go
GODEBUG= /tmp/ia-minimal
GODEBUG=tlsmlkem=0 /tmp/ia-minimal
```

On one runner, both Go 1.25.4 and Go 1.27.1 failed the default handshake at the
5-second deadline, while their identical binaries with `tlsmlkem=0` succeeded
in about 0.28 seconds. No HTTP request, redirect, or torrent download is needed.

No TLS and no Go are needed to reproduce the underlying loss:

```sh
python3 diagnostics/tcp-repro.py --sizes 1438,1439 --rounds 2
```

This sends valid plaintext HTTP to the public HTTPS port. The successful
connection receives nginx's expected 400 response. On the measured runner,
1438 TCP payload bytes + 52 header bytes = 1490 IP bytes succeeded; 1439 + 52
= 1491 failed. The exact payload boundary assumes timestamp options are enabled.
The `--no-df` switch uses Linux `IP_MTU_DISCOVER=IP_PMTUDISC_DONT`.

## Experiments and full artifacts

| Stage | Run | Commit | Runner regions | Purpose |
|---|---|---|---|---|
| 1 | https://github.com/filippo-agent/ct-archive/actions/runs/37052167770 | `98aaf93` | westus3, westus | Interleaved default/classical, equal-size padded classical, MSS900, TLS-record splitting, hybrid-share removal |
| 2 | https://github.com/filippo-agent/ct-archive/actions/runs/37052773599 | `f2862ff` | westus3, centralus | Plaintext HTTP, TCP write splitting, size probes, MSS1440/1441, offloads disabled |
| 3 | https://github.com/filippo-agent/ct-archive/actions/runs/37053272396 | `0d99ae6` | westus3 | Minimal Go 1.25.4/1.27.1, Python size sweep, timestamp-options control, ICMP echo |
| 4 | https://github.com/filippo-agent/ct-archive/actions/runs/37053716621 | `d85ac86` | westus3 | Exact 1490/1491 cutoff, DF-bit control, small ICMP-echo control |

All comparisons within a job used fresh connections and one pinned IPv4
address/SNI. Trials were interleaved and repeated in reverse order. Stage 3
disabled TSO/GSO/GRO before its captures; stage 4 did the same. Stage 2 captured
both enabled and disabled states on the same runner.

The workflow corresponding to each stage is also saved as
`workflow-stage1.yml`, `workflow-stage2.yml`, `workflow-stage3.yml`, or the live
`.github/workflows/probe.yml` (stage 4). GitHub's run UI may retain the original
workflow display name despite subsequent YAML name changes.

Each run uploaded filtered PCAPs and logs as GitHub artifacts with 14-day
retention. Complete copies, including public-handshake TLS key logs and parsed
connection summaries, are preserved on the investigation VM at:

```
/home/exedev/ia-tls-artifacts/run-37052167770/
/home/exedev/ia-tls-artifacts/run-37052773599/
/home/exedev/ia-tls-artifacts/run-37053272396/
/home/exedev/ia-tls-artifacts/run-37053716621/
```

The complete written report is `/home/exedev/ia-tls-findings.md`.

## Permanent small PCAP fixtures

These extracts are committed here so the decisive packet evidence survives
GitHub artifact expiry. No credentials or private HTTP traffic were sent.

* `fixtures/default-vs-mss900.pcap`: stage 1, job 1. Ports 47790 (default
  failure) and 50622 (verified ML-KEM handshake with MSS900). The first flow
  cumulatively acknowledges only SYN, SACKs bytes `[1449,1530)`, and repeatedly
  fails to acknowledge the missing 1448-byte prefix. Captures include normal
  offload super-packets; do not treat their lengths as on-wire IP lengths.
* `fixtures/ip1490-vs-ip1491.pcap`: stage 4. Ports 45578/45580 are the
  timestamp-enabled 1490/1491-byte tests; 54730/54744 are their timestamp-free
  equivalents; 58928 is a larger DF-cleared failure with a SACKed tail.
  TSO/GSO/GRO were disabled. Only eth0's copy is retained.
* `fixtures/SHA256SUMS`: hashes of both extracts.

Full captures use Linux SLL2. `-i any` captures eth0 and its Azure VF, so many
packets appear twice with different interface indices. This is not a
retransmission. `analyze.py` retains eth0 (index 2), reports relative ACK/SACK
ranges and correlates source ports with result logs:

```sh
python3 -m venv /tmp/ia-analysis
/tmp/ia-analysis/bin/pip install scapy
/tmp/ia-analysis/bin/python diagnostics/analyze.py /path/to/artifact-directory
```

## Interpretation cautions

* `raw-*` TLS variants inspect only the first server record. Padding or changing
  ClientHello extensions externally changes the transcript; they are not
  claimed to complete the handshake. The packet loss occurs before that issue
  can arise.
* Splitting TLS records while writing them together did not avoid full-sized
  TCP packets and did not fix the loss. This is not evidence of server
  intolerance to TLS-record fragmentation.
* TCP write splitting preserves the TLS handshake bytes and transcript. Its
  successful ML-KEM handshake retained the normal negotiated MSS; this isolates
  the outbound first-flight packetization without reducing inbound MSS.
* Clearing DF really produced DF-clear 1492/1500-byte packets, but they still
  were not ACKed. It did not silently fix the failure by selecting smaller MSS.
* All tested ICMP echoes, including an 84-byte IP packet, received no reply.
  The large echo tests therefore do not independently measure path MTU.
* Historical upstream default-Go successes exist. Their captures are
  unavailable. Runner region alone is not an explanation: historical eastus
  failed while eastus2 and northcentralus succeeded.
* No external issue was filed, no humans were contacted, and no main-PR code
  was changed. Locating the dropping network component needs additional
  vantage points or network-owner cooperation.
