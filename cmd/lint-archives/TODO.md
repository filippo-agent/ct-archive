# Archive check backlog

## Implemented

- [x] Read small ZIP members through IA extraction URLs or bounded HTTP Range
  requests, using the same metadata checks. Require valid partial responses;
  never consume a full ZIP response if the server ignores Range.
- [x] Compare log metadata and checkpoint origin/size inside the first ZIP with
  the standalone files on prefix hosts. Hosts without Range support retain
  standalone-file and HEAD availability checks.

## Deferred to later PRs

- [ ] Compare the README/CLI origin label with the archive's checkpoint and log
  metadata.
- [ ] Validate the log public key and derive its log ID; compare with `log_id`
  and, where available, independently trusted log information.
- [ ] Parse the full checkpoint (including its root hash) and verify its signature
  with the log public key. Establish trust in that key separately.
- [ ] Extend metadata comparisons to other ZIPs/parts and full checkpoint
  contents, not only the origin and tree size.
- [ ] Sample a random data tile, recompute its leaf hashes, and compare them with
  the corresponding hash tile. Handle RFC 6962 archival leaves and partial tiles.
- [ ] Verify the sampled data's inclusion in the checkpoint root using the
  necessary hash tiles. Pair this with checkpoint signature/key verification.
- [ ] Check ZIP naming/coverage and expected members, including partial
  right-edge tiles, upper-level hash tiles, and issuers. Without an inventory,
  HEAD probes establish expected ZIP availability, not absence of extra files.
- [ ] Compare torrent file lengths with archive objects; consider bounded piece
  sampling rather than downloading the entire archive to check piece hashes.
- [ ] Compare the advertised tree size/root with an independently known final
  checkpoint, when available.
