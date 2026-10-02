package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strconv"
	"strings"

	"github.com/anacrolix/torrent/bencode"
)

// fileReader fetches a small file by name, independent of how it is served.
type fileReader func(name string) ([]byte, error)

// httpFiles handles both direct prefixes and IA's ZIP-member extraction URLs.
func httpFiles(client *http.Client, prefix string) fileReader {
	prefix = strings.TrimRight(prefix, "/") + "/"
	return func(name string) ([]byte, error) {
		return fetch(client, prefix+name)
	}
}

type logInfo struct {
	LogID         *string `json:"log_id"`
	URL           string  `json:"url"`
	SubmissionURL string  `json:"submission_url"`
	MonitoringURL string  `json:"monitoring_url"`
}

type checkpoint struct {
	Origin string
	Size   int64
}

func fetchLogInfo(read fileReader) (logInfo, error) {
	var info logInfo
	data, err := read("log.v3.json")
	if err != nil {
		return info, fmt.Errorf("Failed to fetch log.v3.json: %w", err)
	}
	if err := json.Unmarshal(data, &info); err != nil {
		return info, fmt.Errorf("Invalid JSON in log.v3.json: %w", err)
	}
	if bytes.Equal(bytes.TrimSpace(data), []byte("null")) {
		return info, fmt.Errorf("Invalid JSON in log.v3.json: expected an object")
	}
	return info, nil
}

func fetchCheckpoint(read fileReader) (checkpoint, error) {
	data, err := read("checkpoint")
	if err != nil {
		return checkpoint{}, fmt.Errorf("Failed to fetch checkpoint: %w", err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) < 2 {
		return checkpoint{}, fmt.Errorf("Invalid checkpoint format (expected at least 2 lines)")
	}
	size, err := strconv.ParseInt(strings.TrimSpace(lines[1]), 10, 64)
	if err != nil || size < 0 {
		return checkpoint{}, fmt.Errorf("Invalid checkpoint size: %s", lines[1])
	}
	// Root hash and signature verification are deferred; see TODO.md.
	return checkpoint{Origin: lines[0], Size: size}, nil
}

// lintMetadata applies the same checks to IA-extracted and Range-read ZIP
// members. Expected values come from IA metadata or the standalone files.
func lintMetadata(read fileReader, expected logInfo, expectedSize *int64) []string {
	var errors []string
	info, err := fetchLogInfo(read)
	if err != nil {
		errors = append(errors, err.Error())
	} else {
		if expected.LogID != nil && *expected.LogID != "" {
			actualID := "None"
			if info.LogID != nil {
				actualID = *info.LogID
			}
			if info.LogID == nil || actualID != *expected.LogID {
				errors = append(errors, fmt.Sprintf(
					"log.v3.json log_id '%s' does not match expected log_id '%s'", actualID, *expected.LogID))
			}
		}
		checkURL := func(field, actual, expected string) {
			if expected == "" {
				return
			}
			actual, expected = strings.TrimRight(actual, "/"), strings.TrimRight(expected, "/")
			if actual != expected {
				errors = append(errors, fmt.Sprintf(
					"log.v3.json %s '%s' does not match expected %s '%s'", field, actual, field, expected))
			}
		}
		if expected.URL != "" {
			checkURL("url", info.URL, expected.URL)
		} else {
			checkURL("submission_url", info.SubmissionURL, expected.SubmissionURL)
			checkURL("monitoring_url", info.MonitoringURL, expected.MonitoringURL)
		}
	}
	checkpoint, err := fetchCheckpoint(read)
	if err != nil {
		errors = append(errors, err.Error())
	} else {
		originURL := expected.SubmissionURL
		if originURL == "" {
			originURL = expected.URL
		}
		if originURL != "" && checkpoint.Origin != originFromURL(originURL) {
			errors = append(errors, fmt.Sprintf(
				"checkpoint origin '%s' does not match expected origin '%s'", checkpoint.Origin, originFromURL(originURL)))
		}
		if expectedSize != nil && checkpoint.Size != *expectedSize {
			errors = append(errors, fmt.Sprintf(
				"checkpoint size %d does not match expected size %d", checkpoint.Size, *expectedSize))
		}
	}
	return errors
}

func originFromURL(url string) string {
	return strings.TrimRight(strings.TrimPrefix(strings.TrimPrefix(url, "https://"), "http://"), "/")
}

func zipCount(size int64) int64 {
	const entriesPerZip = 256 * 256 * 256
	n := size / entriesPerZip
	if size%entriesPerZip > 0 {
		n++
	}
	return n
}

// fetch is for metadata and torrents, never ZIPs. Bound reads in case a
// misconfigured endpoint serves a ZIP (including one without Content-Length).
func fetch(client *http.Client, url string) ([]byte, error) {
	response, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", response.StatusCode)
	}
	const limit = 64 << 20
	if response.ContentLength > limit {
		return nil, fmt.Errorf("response exceeds %d bytes", limit)
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if len(data) > limit {
		return nil, fmt.Errorf("response exceeds %d bytes", limit)
	}
	return data, nil
}

func lintTorrent(client *http.Client, url string, expectedFiles []string) []string {
	if url == "" {
		return nil
	}
	data, err := fetch(client, url)
	if err != nil {
		return []string{fmt.Sprintf("Failed to fetch torrent: %v", err)}
	}
	files, err := torrentFiles(data)
	if err != nil {
		return []string{fmt.Sprintf("Failed to parse torrent: %v", err)}
	}
	missingSet := make(map[string]bool)
	for _, name := range expectedFiles {
		if !files[name] {
			missingSet[name] = true
		}
	}
	var missing []string
	for name := range missingSet {
		missing = append(missing, name)
	}
	slices.Sort(missing)
	if len(missing) == 0 {
		return nil
	}
	suffix := ""
	if len(missing) > 5 {
		suffix = " ..."
	}
	return []string{fmt.Sprintf("Torrent is missing %d files: %s%s",
		len(missing), strings.Join(missing[:min(5, len(missing))], ", "), suffix)}
}

// Only the file list matters here; do not impose tracker, hash, or other
// metainfo validation that the Python linter does not perform.
func torrentFiles(data []byte) (map[string]bool, error) {
	var torrent struct {
		Info struct {
			Name  string `bencode:"name"`
			Files []struct {
				Path []string `bencode:"path"`
			} `bencode:"files"`
		} `bencode:"info"`
	}
	if err := bencode.Unmarshal(data, &torrent); err != nil {
		return nil, err
	}
	files := make(map[string]bool)
	if torrent.Info.Files != nil {
		for _, file := range torrent.Info.Files {
			if file.Path == nil {
				return nil, fmt.Errorf("torrent file has no path")
			}
			files[strings.Join(file.Path, "/")] = true
		}
	} else if torrent.Info.Name != "" {
		files[torrent.Info.Name] = true
	}
	return files, nil
}
