# Internet Archive / Go TLS timeout investigation

Date: October 2, 2026. Investigation performed in this top-level Shelley conversation.
Repository: `/home/exedev/ia-tls-top`, isolated fork branch `diagnose-ia-tls-top`.
The application PR branch was not modified; no outside maintainers were contacted.

## Conclusion

**High confidence: the reproduced timeout is caused by loss of oversized outbound TCP packets before the peer can assemble the ClientHello, not ML-KEM negotiation or a Go TLS handshake-state bug.**

The last experiment measured an effective client-to-EU packet-size ceiling of **1490 bytes of IPv4 packet**: 1490 was acknowledged and answered; 1491 was repeatedly retransmitted without acknowledgment. This is strongly consistent with a **path-MTU black hole**. Neither the responsible hop/operator nor the precise underlying mechanism (e.g. tunnel MTU versus size-based filtering) is identified from a client-side capture alone.

`GODEBUG=tlsmlkem=0` is effective because it shrinks the hello. In Go 1.25.4, with this SNI and h2/http/1.1 ALPN, the first TLS record is 1529 bytes by default and 307 bytes with classical curves. The normal TCP path sends 1448 bytes of the former in a 1500-byte IP packet, then its 81-byte tail. Only the tail arrives. The peer cannot deliver a contiguous ClientHello to TLS.

**This is not evidence that IA cannot do ML-KEM.** Unchanged default Go TLS negotiates X25519MLKEM768 on affected runners when TCP MSS is reduced, or when the same hello is sent in spaced small writes. Default Go 1.25.4 also succeeds from this VM. Earlier successful application CI runs remain valid observations; their network routes, final redirect endpoints, and packet sizes were not captured, so their difference cannot be explained conclusively.

## First controlled experiment

Run 37052157726, commit `f185e59877d05ac2312b7a323f65fdded81e93fc`.
One ubuntu-latest runner, Go 1.25.4, pinned EU IPv4 `145.116.0.213`, SNI `dn760103.eu.archive.org`. Fresh connections, three interleaved rounds; default and classical each occur twice per round.

| Variant | Successful / attempted | Measurement |
|---|---:|---|
| Default | 0/6 | Full TLS handshake |
| Classical curves | 6/6 | Full TLS handshake |
| Classical padded to 1529 bytes | 0/3 | First server flight only |
| Default, TCP writes of 600/600/329 bytes with 100 ms gaps | 3/3 | Full TLS handshake, ML-KEM selected |
| Default, TLS records split at 600-byte payloads, all written together | 0/3 | Full TLS handshake |
| Default, pre-connect TCP_MAXSEG=600 | 3/3 | Full TLS handshake, ML-KEM selected |
| Classical padded to 2000 bytes | 0/3 | First server flight only |

Padding controls use a generated classical ClientHello with TLS padding extension 21 added and enclosing lengths adjusted. They are *not* full authenticated handshake tests: changing the hello outside crypto/tls would invalidate its transcript. This is sufficient to test transport delivery and first-flight response. Padding controls also receive server flights locally.

### Packet-level failure

`evidence/run1/ia-tls-evidence/eu.pcap`, stream 0, client port 39692:

- SYN and SYN-ACK advertise MSS 1460; TCP timestamps yield 1448-byte maximum data segments.
- First hello is 1529 bytes. With offload enabled, the local capture initially presents the unsegmented buffer; this is **not** a 1581-byte wire-packet claim.
- Frame 8: peer ACK=1, SACK [1449,1530). The 81-byte tail is received but the entire 1448-byte prefix is missing.
- Frames 10, 12, 14, 16, 18, 20: retransmission of the prefix, IP length 1500, without ACK advancement or a TLS response.
- The application reaches its 10-second deadline.

`evidence/run1/default-packets.tsv` and `split600-packets.tsv` preserve the extracted comparison. The split control keeps SYN MSS 1460 but sends IP packets 652, 652, and 381 bytes; all bytes are cumulatively ACKed and the server selects group 0x11ec (X25519MLKEM768).

Capture caveats: `-i any` in this first run observes the same traffic at multiple interfaces, so near-identical adjacent frames are capture duplicates, not evidence of real retransmission. Longer-interval retransmissions are genuine. Some failed sockets continue retransmission after the application closes; later suites use abortive close to reduce that clutter. All original captures are preserved.

## Offload and endpoint controls

Run 37052745220, commit `fdca79ca1d460ae2eda5ba305099c6861e687298`, two independent runners.

Each tested the size sweep with segmentation/coalescing offloads enabled, then disabled TSO/GSO/GRO with `ethtool`, and repeated it. Both runners gave the same result in both conditions:

- Classical hello size 1430 => IP length 1482 => acknowledged, server flight received.
- Classical hello size 1440 => IP length 1492 => no payload acknowledgment, timeout.
- Larger classical hellos fail too.
- Default full handshake with MSS 1300, 1400, 1420, or 1440 succeeds with ML-KEM; MSS 1460 fails.

With offloads disabled, capture explicitly shows the default-shaped hello's 1500-byte prefix packet and 133-byte tail packet, and the same SACK gap. This rules out a mere capture/offload interpretation problem and strongly disfavors TSO/GSO/GRO as the cause.

The US mirror `ia801402.us.archive.org` (`207.241.228.142`) succeeds for all initial-suite variants on both runners. Important confound: its received SYN-ACK advertises **MSS 1396**, whereas EU advertises 1460. Its outgoing client data packets are at most 1436 bytes in the offload-disabled capture. Thus US success is not a clean same-packet-size comparison of geography or server software; MSS alone avoids the EU-observed threshold. The capture cannot establish whether the US MSS is set at the host or clamped along the path.

An initial post-handshake control accidentally used Go's default adaptive record sizing, producing a 1208-byte first encrypted write despite a larger HTTP request. It succeeded but did **not** exercise large packets; that confound was identified and corrected in the next run.

## Exact boundary, encrypted application data, minimal reproducer

Run 37053056282, commit `acb20a2`, Go 1.25.4 on another ubuntu-latest runner. TSO/GSO/GRO disabled. Capture on eth0 includes all ICMP, without requiring the EU host address in ICMP packets.

### Byte-level threshold

Classical padded ClientHello sweep, fresh connections:

- 1430 through 1438 bytes of TCP payload succeed, IP lengths 1482 through **1490**.
- 1439 and 1440 bytes fail, IP lengths **1491** and 1492.
- `TCP_MAXSEG=1450` makes the unchanged 1529-byte default hello succeed (largest outbound packet 1490); 1452 fails (1492).

`evidence/run3/ia-exact-boundary/boundary.pcap`:

- Port 48096, frame 100: IP length 1490, DF=1, payload 1438, followed by frame 101 ACK=1439 and a server flight.
- Port 48106, frame 112: IP length 1491, DF=1, payload 1439. Frames 113–116 retransmit it, with no data acknowledgment. A later peer ACK remains 1.

These are **TCP segments**, not fragmented IP datagrams or missing TLS records.

### Not specific to ClientHello parsing

The probe first completes a classical TLS 1.3 handshake, then sends a HEAD request with an 1800-byte padding header. `DynamicRecordSizingDisabled=true` ensures a 1910-byte encrypted TLS record.

- Port 40168: handshake completes. The request becomes a 1500-byte IP packet carrying 1448 bytes, plus its tail. Peer ACK stays 369, SACK [1817,2279): the tail is received, the 1448-byte prefix is missing. The HTTP read times out. Any server encrypted session-ticket bytes do not acknowledge the missing request prefix.
- Same operation on a fresh connection, with only the encrypted write split into spaced 600-byte chunks: HTTP 200.

This independently rejects a ClientHello parser/reassembly explanation. It reproduces the loss with encrypted application data after TLS negotiation is complete.

### ICMP

No received ICMP appears in this capture, including no fragmentation-needed message. One small and one large DF ping both get no response, so those pings say nothing useful about the MTU. No claim is made about whether an intermediate hop generated ICMP that was lost elsewhere. The runner's `net.ipv4.tcp_mtu_probing` was 0.

### Minimal TLS-only reproducer

Source: `cmd/min-repro/main.go` (standard library only, Linux).

```sh
GOTOOLCHAIN=go1.25.4 go build -o /tmp/ia-min ./cmd/min-repro
/tmp/ia-min
/tmp/ia-min -mss 1400
GODEBUG=tlsmlkem=0 /tmp/ia-min
```

Observed on the same runner:

1. Default: timeout after 10.005 s, no negotiated curve.
2. MSS 1400: success in 161 ms, X25519MLKEM768.
3. tlsmlkem=0: success in 165 ms, X25519.

No torrent download, HTTP, redirects, concurrency, custom trust roots, or application transport is necessary. IP is pinned by default; use `-addr` if DNS changes. SNI and normal certificate verification remain enabled. A successful run on an unaffected path does not falsify this path-dependent reproducer.

## Relationship to tldr.fail

The linked page describes larger post-quantum ClientHellos exposing implementations that wrongly assume a single TCP read returns the entire hello. This shares the *trigger* of a larger ClientHello but not the demonstrated mechanism here. Here splitting TCP writes helps; the transport's cumulative ACK never advances over the large missing segment; and the failure recurs in encrypted application data after a completed classical handshake. The page was fetched and preserved as `evidence/tldr-fail.html`.

## Confidence and remaining uncertainty

- **High:** removing ML-KEM avoids this failure by changing first-flight packet sizing; the endpoint can negotiate ML-KEM successfully.
- **High:** reproduced failures are outbound TCP-delivery failures, not a TLS alert, HRR loop, slow crypto, HTTP/2 issue, or torrent/application problem.
- **High:** a packet-size-dependent black hole exists on sampled runner-to-EU connections, with measured 1490/1491 boundary on the final runner.
- **Strong inference, not hop-level proof:** an MTU/PMTUD failure rather than intentional packet-length filtering. DF packets above a sharp ceiling vanish; no useful ICMP returns.
- **Unknown:** responsible hop/operator, encapsulation/configuration, whether Azure/transit/IA ingress, and why earlier uncaptured CI runs succeeded. Client captures cannot determine these. A capture near the destination or cooperative network telemetry is the next discriminating evidence.
- No blanket incompatibility claim, no proposed crypto/tls downgrade, and no recommendation to change default TLS record framing follows from these data.

## Evidence preservation

Primary evidence is in `evidence/run1`, `evidence/run2`, and `evidence/run3`, including original pcaps, logs, generated hellos, public-request TLS key logs, environment records, and run IDs/commits. `analysis/summarize.py` produces per-connection ACK/size summaries from captures and local-port labels. Missing Wireshark-decoded groups in summaries can reflect reassembly/out-of-order dissection; full-handshake Go logs are the primary completion result.

The already-running prior subagent's initial artifacts were independently downloaded into `evidence/other-run` and inspected; its two runners show the same SACK gap and MSS workaround. Those corroborate but are not needed for the conclusions above, which use experiments performed here. No additional subagents were started for this investigation.
