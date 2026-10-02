package main

import (
	"bytes"
	"crypto/sha1"
	"errors"
	"fmt"
	"math"
	"math/rand/v2"
	"net/http"
	"regexp"
	"slices"
	"strings"

	"github.com/anacrolix/torrent/metainfo"
)

// archiveObject is supplied by the archive inventory, never by the torrent.
// URL already has its path encoded; Size is -1 when metadata/HEAD cannot tell.
type archiveObject struct {
	URL  string
	Size int64
}

const torrentPieceLimit = 16 << 20

var torrentNumberedZip = regexp.MustCompile(`^[0-9]{3}\.zip$`)

func lintTorrentObjects(client *http.Client, url string, objects map[string]archiveObject) []string {
	if url == "" {
		return nil
	}
	data, err := fetch(client, url)
	if err != nil {
		return []string{fmt.Sprintf("Failed to fetch torrent: %v", err)}
	}
	mi, err := metainfo.Load(bytes.NewReader(data))
	if err != nil {
		return []string{fmt.Sprintf("Failed to parse torrent: %v", err)}
	}
	info, err := mi.UnmarshalInfo()
	if err != nil {
		return []string{fmt.Sprintf("Failed to parse torrent info: %v", err)}
	}

	var diagnostics []string
	if !info.HasV1() {
		return []string{"Torrent has no v1 file/piece layout"}
	}
	if !torrentSafePath([]string{info.Name}) ||
		(info.NameUtf8 != "" && !torrentSafePath([]string{info.NameUtf8})) {
		diagnostics = append(diagnostics, "Torrent has an unsafe or empty name")
	}
	if info.Length < 0 || (info.Files != nil && info.Length != 0) {
		diagnostics = append(diagnostics, "Torrent has an invalid single-file length or mixed single/multi-file layout")
	}
	if info.Files != nil && len(info.Files) == 0 {
		diagnostics = append(diagnostics, "Torrent has an empty multi-file layout")
	}
	switch {
	case info.PieceLength <= 0:
		diagnostics = append(diagnostics, "Torrent piece length must be positive")
	case info.PieceLength > torrentPieceLimit:
		// Do not silently imply a piece was checked, or download an unbounded
		// piece. The archive torrents currently use at most 16 MiB pieces.
		diagnostics = append(diagnostics, fmt.Sprintf(
			"Torrent piece length %d exceeds the supported sampling limit %d", info.PieceLength, torrentPieceLimit))
	}
	if len(info.Pieces)%sha1.Size != 0 {
		diagnostics = append(diagnostics, "Torrent piece hashes are not a multiple of 20 bytes")
	}

	files := info.Files
	if files == nil {
		files = []metainfo.FileInfo{{Path: []string{info.BestName()}, Length: info.Length}}
	}
	seen := make(map[string]bool)
	var total int64
	layoutValid := true
	for _, file := range files {
		name := strings.Join(file.BestPath(), "/")
		if !torrentSafePath(file.Path) ||
			(len(file.PathUtf8) != 0 && !torrentSafePath(file.PathUtf8)) {
			diagnostics = append(diagnostics, fmt.Sprintf("Torrent has unsafe file path %q", name))
		}
		if seen[name] {
			diagnostics = append(diagnostics, fmt.Sprintf("Torrent repeats file %q", name))
		}
		seen[name] = true
		object, listed := objects[name]
		if listed && object.Size < -1 {
			diagnostics = append(diagnostics, fmt.Sprintf("%s: invalid expected object size %d", name, object.Size))
		} else if listed && object.Size >= 0 && file.Length != object.Size {
			diagnostics = append(diagnostics, fmt.Sprintf(
				"%s: torrent length %d differs from object size %d", name, file.Length, object.Size))
		}
		if file.Length < 0 || file.Length > math.MaxInt64-total {
			diagnostics = append(diagnostics, fmt.Sprintf("%s: negative torrent length or total length overflow", name))
			layoutValid = false
			continue
		}
		total += file.Length
	}
	if layoutValid && info.PieceLength > 0 {
		count := total / info.PieceLength
		if total%info.PieceLength != 0 {
			count++
		}
		if count != int64(len(info.Pieces)/sha1.Size) {
			diagnostics = append(diagnostics, fmt.Sprintf(
				"Torrent has %d piece hashes, expected %d for %d bytes", len(info.Pieces)/sha1.Size, count, total))
		}
	}
	var missing []string
	for name := range objects {
		if !seen[name] {
			missing = append(missing, name)
		}
	}
	slices.Sort(missing)
	if len(missing) != 0 {
		suffix := ""
		if len(missing) > 5 {
			suffix = " ..."
		}
		diagnostics = append(diagnostics, fmt.Sprintf("Torrent is missing %d files: %s%s",
			len(missing), strings.Join(missing[:min(5, len(missing))], ", "), suffix))
	}
	// Unknown object sizes and unlisted files are valid here: prefix inventories
	// need only list required ZIPs. Neither can supply URLs or sampling bytes.
	if len(diagnostics) != 0 || total == 0 {
		return diagnostics
	}
	type sampleRange struct {
		name         string
		offset       int64 // File start in the concatenated v1 stream.
		first, count int64 // Fully contained global piece indices.
	}
	var candidates []sampleRange
	var start, eligible int64
	for _, file := range files {
		end := start + file.Length
		name := strings.Join(file.BestPath(), "/")
		object, listed := objects[name]
		if listed && object.Size == file.Length && object.URL != "" &&
			torrentNumberedZip.MatchString(name) && file.Length > 0 {
			// Choose uniformly among eligible pieces, not files. Only pieces
			// wholly inside a known numbered ZIP qualify, avoiding cross-file
			// probes and tiny attachments. One suffix probe plus one piece
			// bounds successful payloads to 16 MiB+1, without any ZIP parsing.
			// Piece reads use <=1 MiB chunks so each gets its own client
			// timeout, rather than timing the entire large piece transfer.
			first := start / info.PieceLength
			if start%info.PieceLength != 0 {
				first++
			}
			last := end / info.PieceLength
			if end == total && total%info.PieceLength != 0 {
				last++ // Include the short last piece only if contained here.
			}
			if last > first {
				candidates = append(candidates, sampleRange{name, start, first, last - first})
				eligible += last - first
			}
		}
		start = end
	}
	if eligible == 0 {
		// No fully contained known ZIP piece: keep metadata checks only.
		return diagnostics
	}
	choice := rand.Int64N(eligible)
	for _, candidate := range candidates {
		if choice >= candidate.count {
			choice -= candidate.count
			continue
		}
		piece := candidate.first + choice
		globalOffset := piece * info.PieceLength
		offset := globalOffset - candidate.offset
		length := min(info.PieceLength, total-globalOffset)
		object := objects[candidate.name]
		r := &rangeZipReaderAt{client: client, url: object.URL, size: object.Size}
		context := fmt.Sprintf("%s: torrent piece %d at offset %d", candidate.name, piece, offset)
		if _, err := r.fetchRange(0, 1, true); err != nil {
			if errors.Is(err, errRangeUnsupported) {
				// A 200 is closed unread; never fall back to a full ZIP GET.
				return diagnostics
			}
			return append(diagnostics, fmt.Sprintf("%s: Range probe: %v", context, err))
		}
		if r.size != object.Size {
			return append(diagnostics, fmt.Sprintf(
				"%s: Range total %d differs from object/torrent length %d", context, r.size, object.Size))
		}
		hash := sha1.New()
		for read := int64(0); read < length; {
			chunkOffset := offset + read
			chunkLength := min(int64(rangeZipWindowSize), length-read)
			data, err := r.fetchRange(chunkOffset, chunkLength, false)
			if err != nil {
				return append(diagnostics, fmt.Sprintf("%s: chunk at offset %d: %v", context, chunkOffset, err))
			}
			hash.Write(data)
			read += chunkLength
		}
		if !bytes.Equal(hash.Sum(nil), info.Pieces[piece*sha1.Size:(piece+1)*sha1.Size]) {
			return append(diagnostics, fmt.Sprintf("%s: SHA-1 does not match torrent piece hash", context))
		}
		break
	}
	return diagnostics
}

func torrentSafePath(parts []string) bool {
	if len(parts) == 0 {
		return false
	}
	for _, part := range parts {
		if part == "" || part == "." || part == ".." || strings.ContainsAny(part, "/\\:\x00") {
			return false
		}
		for _, c := range part {
			if c < 0x20 || c == 0x7f {
				return false
			}
		}
	}
	return true
}
