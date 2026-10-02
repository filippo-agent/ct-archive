package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

var (
	iaIDPattern        = regexp.MustCompile(`https://archive\.org/details/([^\s|]+)`)
	iaExtensionPattern = regexp.MustCompile(`_ext[1-9]\d*$`)
)

// IA metadata fields can be either a string or a list of strings.
type iaStrings []string

func (s *iaStrings) UnmarshalJSON(data []byte) error {
	if bytes.Equal(bytes.TrimSpace(data), []byte("null")) {
		*s = nil
		return nil
	}
	var single string
	if err := json.Unmarshal(data, &single); err == nil {
		*s = []string{single}
		return nil
	}
	var list []string
	if err := json.Unmarshal(data, &list); err != nil {
		return fmt.Errorf("expected a string or list of strings: %w", err)
	}
	*s = list
	return nil
}

func (s iaStrings) first() string {
	if len(s) == 0 {
		return ""
	}
	return s[0]
}

type iaFile struct {
	Name   string `json:"name"`
	Source string `json:"source"`
}

type iaItem struct {
	Metadata json.RawMessage `json:"metadata"`
	Files    []iaFile        `json:"files"`
}

type iaMetadata struct {
	Subject       iaStrings       `json:"subject"`
	Collection    iaStrings       `json:"collection"`
	LogID         iaStrings       `json:"ctlogid"`
	URL           iaStrings       `json:"cturl"`
	SubmissionURL iaStrings       `json:"ctsubmissionurl"`
	MonitoringURL iaStrings       `json:"ctmonitoringurl"`
	LogSize       json.RawMessage `json:"ctlogsize"`
}

// lintIA checks an archive, including its extension items. The
// caller owns the client's timeout and transport; every request uses it.
func lintIA(client *http.Client, e entry) []string {
	matches := iaIDPattern.FindAllStringSubmatch(e.location, -1)
	if len(matches) == 0 {
		return []string{"No Internet Archive item identifier found in URL"}
	}
	ids := make([]string, len(matches))
	locations := make([]string, len(matches))
	for i, match := range matches {
		ids[i] = match[1]
		locations[i] = "https://archive.org/details/" + ids[i]
	}

	var errors []string
	expectedLocation := strings.Join(locations, " ")
	if e.location != expectedLocation {
		errors = append(errors, fmt.Sprintf("Archive location should be '%s'", expectedLocation))
	}
	expectedExtensions := make([]string, len(ids)-1)
	for i := range expectedExtensions {
		expectedExtensions[i] = fmt.Sprintf("%s_ext%d", ids[0], i+1)
	}
	if !slices.Equal(ids[1:], expectedExtensions) {
		errors = append(errors, fmt.Sprintf(
			"Extension items must be named consecutively: expected %v, found %v",
			expectedExtensions, ids[1:]))
	}

	items := make([]iaItem, len(ids))
	fetchErrors := make([]error, len(ids))
	totalZips := 0
	for i, id := range ids {
		data, err := fetch(client, "https://archive.org/metadata/"+id)
		if err != nil {
			fetchErrors[i] = fmt.Errorf("Failed to fetch metadata: %w", err)
			continue
		}
		if err := json.Unmarshal(data, &items[i]); err != nil {
			fetchErrors[i] = fmt.Errorf("Invalid JSON in metadata: %w", err)
			continue
		}
		for _, file := range items[i].Files {
			if strings.HasSuffix(file.Name, ".zip") {
				totalZips++
			}
		}
	}
	for i, id := range ids {
		if fetchErrors[i] != nil {
			errors = append(errors, fmt.Sprintf("%s: %v", id, fetchErrors[i]))
			continue
		}
		torrentURL := ""
		// IA's torrent covers only the base item, not its extension items.
		if i == 0 {
			torrentURL = e.torrentURL
		}
		for _, diagnostic := range lintIAPart(client, id, items[i], totalZips, torrentURL) {
			errors = append(errors, id+": "+diagnostic)
		}
	}
	return errors
}

func lintIAPart(client *http.Client, id string, item iaItem, totalZips int, torrentURL string) []string {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(item.Metadata, &fields); err != nil && len(item.Metadata) != 0 {
		return []string{fmt.Sprintf("Invalid JSON in metadata: %v", err)}
	}
	if len(fields) == 0 {
		return []string{fmt.Sprintf("Item %s not found or has no metadata", id)}
	}
	var metadata iaMetadata
	if err := json.Unmarshal(item.Metadata, &metadata); err != nil {
		return []string{fmt.Sprintf("Invalid JSON in metadata: %v", err)}
	}

	var errors []string
	if !slices.Contains(metadata.Subject, "certificate transparency log") {
		errors = append(errors, fmt.Sprintf("Missing 'certificate transparency log' topic (has: %v)", metadata.Subject))
	}
	logID := metadata.LogID.first()
	ctURL := metadata.URL.first()
	submissionURL := metadata.SubmissionURL.first()
	monitoringURL := metadata.MonitoringURL.first()
	if logID == "" {
		errors = append(errors, "Missing 'ctlogid' metadata")
	}
	if ctURL == "" && (submissionURL == "" || monitoringURL == "") {
		errors = append(errors, "Missing URL metadata: expected either 'cturl' or both 'ctsubmissionurl' and 'ctmonitoringurl'")
	}
	allowedCollection := false
	for _, collection := range metadata.Collection {
		if collection == "opensource_media" || collection == "datasets" || collection == "datasets_unsorted" {
			allowedCollection = true
			break
		}
	}
	if !allowedCollection {
		errors = append(errors, fmt.Sprintf(
			"Collection should be one of {'opensource_media', 'datasets', 'datasets_unsorted'} (has: %v)",
			metadata.Collection))
	}

	logSize, present, sizeErr := iaLogSize(metadata.LogSize)
	switch {
	case sizeErr != nil:
		errors = append(errors, fmt.Sprintf("Invalid ctlogsize value: %s", metadata.LogSize))
	case !present:
		errors = append(errors, "Missing 'ctlogsize' metadata")
	default:
		expectedZips := zipCount(logSize)
		if int64(totalZips) != expectedZips {
			errors = append(errors, fmt.Sprintf(
				"Expected %d zip files across all items based on ctlogsize %d, found %d",
				expectedZips, logSize, totalZips))
		}
	}

	if logID != "" || ctURL != "" || submissionURL != "" || monitoringURL != "" {
		var zips []string
		for _, file := range item.Files {
			if strings.HasSuffix(file.Name, ".zip") {
				zips = append(zips, file.Name)
			}
		}
		slices.Sort(zips)
		if len(zips) == 0 {
			errors = append(errors, "No zip files found in item")
		} else {
			firstZip := zips[0]
			if !iaExtensionPattern.MatchString(id) {
				if !slices.Contains(zips, "000.zip") {
					// The Python linter also returns before checking the torrent.
					return append(errors, "No 000.zip found in base item")
				}
				firstZip = "000.zip"
			}
			baseURL := "https://archive.org/download/" + id + "/" + firstZip
			logJSON, err := fetchLogInfo(client, baseURL+"/log.v3.json")
			if err != nil {
				errors = append(errors, err.Error())
			} else {
				actualID := "None"
				if logJSON.LogID != nil {
					actualID = *logJSON.LogID
				}
				if logID != "" && (logJSON.LogID == nil || *logJSON.LogID != logID) {
					errors = append(errors, fmt.Sprintf(
						"log.v3.json log_id '%s' does not match metadata ctlogid '%s'", actualID, logID))
				}
				if ctURL != "" {
					if actual, expected := strings.TrimRight(logJSON.URL, "/"), strings.TrimRight(ctURL, "/"); actual != expected {
						errors = append(errors, fmt.Sprintf(
							"log.v3.json url '%s' does not match metadata cturl '%s'", actual, expected))
					}
				} else {
					if actual, expected := strings.TrimRight(logJSON.SubmissionURL, "/"), strings.TrimRight(submissionURL, "/"); submissionURL != "" && actual != expected {
						errors = append(errors, fmt.Sprintf(
							"log.v3.json submission_url '%s' does not match metadata ctsubmissionurl '%s'", actual, expected))
					}
					if actual, expected := strings.TrimRight(logJSON.MonitoringURL, "/"), strings.TrimRight(monitoringURL, "/"); monitoringURL != "" && actual != expected {
						errors = append(errors, fmt.Sprintf(
							"log.v3.json monitoring_url '%s' does not match metadata ctmonitoringurl '%s'", actual, expected))
					}
				}
			}
			checkpoint, err := fetchCheckpoint(client, baseURL+"/checkpoint")
			if err != nil {
				errors = append(errors, err.Error())
			} else {
				originURL := submissionURL
				if originURL == "" {
					originURL = ctURL
				}
				expectedOrigin := originFromURL(originURL)
				if originURL != "" && checkpoint.Origin != expectedOrigin {
					errors = append(errors, fmt.Sprintf(
						"checkpoint origin '%s' does not match URL metadata '%s'", checkpoint.Origin, expectedOrigin))
				}
				if present && sizeErr == nil && logSize != 0 && checkpoint.Size != logSize {
					errors = append(errors, fmt.Sprintf(
						"checkpoint size %d does not match ctlogsize %d", checkpoint.Size, logSize))
				}
			}
		}
	}

	var originalFiles []string
	for _, file := range item.Files {
		if file.Source == "original" && file.Name != "" && !strings.HasSuffix(file.Name, "_files.xml") {
			originalFiles = append(originalFiles, file.Name)
		}
	}
	return append(errors, lintTorrent(client, torrentURL, originalFiles)...)
}

// iaLogSize preserves integer precision for both JSON integers and strings.
// A JSON number may also be a float, which Python's int() truncates.
func iaLogSize(raw json.RawMessage) (size int64, present bool, err error) {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || bytes.Equal(raw, []byte("null")) {
		return 0, false, nil
	}
	if raw[0] == '"' {
		var value string
		if err := json.Unmarshal(raw, &value); err != nil {
			return 0, true, err
		}
		if value == "" {
			return 0, false, nil
		}
		size, err := strconv.ParseInt(strings.TrimSpace(value), 10, 64)
		return size, true, err
	}
	var number json.Number
	if err := json.Unmarshal(raw, &number); err != nil {
		return 0, true, err
	}
	size, err = number.Int64()
	if err != nil {
		value, floatErr := number.Float64()
		if floatErr != nil || math.IsNaN(value) || math.IsInf(value, 0) || value >= 1<<63 || value < -(1<<63) {
			return 0, true, fmt.Errorf("ctlogsize is not an int64")
		}
		return int64(value), value != 0, nil
	}
	// Zero as a number is false in Python, while the string "0" is true.
	return size, size != 0, nil
}
