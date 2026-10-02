# Deferred archive checks

This is the backlog for later PRs, not checks performed by the current linter.

- [ ] Compare the README/CLI origin label with the archive's checkpoint and log
  metadata.
- [ ] Validate the log public key and derive its log ID; compare with `log_id`
  and, where available, independently trusted log information.
- [ ] Parse the full checkpoint (including its root hash) and verify its signature
  with the log public key. Establish trust in that key separately.
- [ ] Read selected ZIP members using bounded HTTP Range requests. Require valid
  partial responses; never consume a full ZIP if the server ignores Range.
  Keep HEAD-only availability checks for hosts without Range support.
- [ ] Compare metadata and checkpoints inside sampled ZIPs with the standalone
  files and with other archive parts.
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
