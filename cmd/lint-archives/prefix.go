package main

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// Non-IA archives expose metadata and numbered ZIPs directly under a URL prefix.
func lintPrefix(client *http.Client, e entry) []string {
	u, err := url.Parse(e.location)
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") ||
		u.RawQuery != "" || u.Fragment != "" || len(strings.Fields(e.location)) != 1 {
		return []string{"Expected a single HTTP(S) URL prefix without a query or fragment"}
	}
	baseURL := strings.TrimRight(e.location, "/") + "/"
	var errors []string
	info, infoErr := fetchLogInfo(client, baseURL+"log.v3.json")
	if infoErr != nil {
		errors = append(errors, infoErr.Error())
	} else {
		if info.LogID == nil || *info.LogID == "" {
			errors = append(errors, "Missing log_id in log.v3.json")
		}
		if info.URL == "" && (info.SubmissionURL == "" || info.MonitoringURL == "") {
			errors = append(errors, "Missing URLs in log.v3.json: expected either url or both submission_url and monitoring_url")
		}
	}
	checkpoint, err := fetchCheckpoint(client, baseURL+"checkpoint")
	if err != nil {
		// Without a tree size we cannot determine the expected ZIP inventory.
		return append(errors, err.Error())
	}
	if infoErr == nil {
		originURL := info.SubmissionURL
		if originURL == "" {
			originURL = info.URL
		}
		if originURL != "" && checkpoint.Origin != originFromURL(originURL) {
			errors = append(errors, fmt.Sprintf(
				"checkpoint origin '%s' does not match log.v3.json URL '%s'", checkpoint.Origin, originFromURL(originURL)))
		}
	}

	n := zipCount(checkpoint.Size)
	// Match photocamera-archiver's 000.zip–999.zip limit, and bound the number
	// of probes even if the unsigned checkpoint advertises an absurd size.
	if n > 1000 {
		return append(errors, fmt.Sprintf("checkpoint implies %d ZIPs; at most 1000 supported", n))
	}
	var zips []string
	for i := int64(0); i < n; i++ {
		name := fmt.Sprintf("%03d.zip", i)
		zips = append(zips, name)
		if err := headZip(client, baseURL+name); err != nil {
			errors = append(errors, fmt.Sprintf("%s: %v", name, err))
		}
	}
	// There is no directory listing: check required ZIPs, not absence of extras.
	return append(errors, lintTorrent(client, e.torrentURL, zips)...)
}

func headZip(client *http.Client, url string) error {
	// Never fall back to a full GET, including when HEAD is unsupported.
	response, err := client.Head(url)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("HEAD returned HTTP %d", response.StatusCode)
	}
	if response.ContentLength == 0 {
		return fmt.Errorf("ZIP is empty")
	}
	return nil
}
