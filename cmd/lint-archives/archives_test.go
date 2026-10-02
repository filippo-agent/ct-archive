package main

import (
	"net/http"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"
)

func TestArchives(t *testing.T) {
	if testing.Short() {
		t.Skip("archive checks require network access")
	}
	readme, err := os.ReadFile("../../README.md")
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Timeout: 30 * time.Second}
	torrentLink := regexp.MustCompile(`\[\.torrent\]\(([^)]+)\)`)
	entries := 0
	for line := range strings.SplitSeq(string(readme), "\n") {
		if !strings.HasPrefix(line, "|") {
			continue
		}
		cells := strings.Split(line, "|")
		if len(cells) < 4 {
			continue
		}
		origin := strings.TrimSpace(cells[1])
		if origin == "Log Origin" || strings.Trim(origin, "-: ") == "" {
			continue
		}
		e := entry{
			origin:   origin,
			location: strings.TrimSuffix(strings.TrimSpace(cells[2]), " †"),
		}
		if match := torrentLink.FindStringSubmatch(cells[3]); match != nil {
			e.torrentURL = match[1]
		}
		entries++
		t.Run(e.origin, func(t *testing.T) {
			t.Parallel()
			if !strings.Contains(e.location, "https://") && !strings.Contains(e.location, "http://") {
				t.Skip("no archive URL")
			}
			diagnostics, supported := lintArchive(client, e)
			if !supported {
				t.Skip("archive host not yet supported")
			}
			for _, diagnostic := range diagnostics {
				t.Error(diagnostic)
			}
		})
	}
	if entries == 0 {
		t.Fatal("no archive entries found in README")
	}
}
