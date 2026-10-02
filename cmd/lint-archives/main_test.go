package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestRun(t *testing.T) {
	for _, tt := range []struct {
		name   string
		args   []string
		status int
		want   string
	}{
		{"valid", []string{"-origin", "log.example/log", "-url", "https://archive.org/details/base"}, 0, "  OK"},
		{"invalid item", []string{"-origin", "log.example/log", "-url", "https://archive.org/details/missing"}, 1, "  ERROR:"},
		{"unsupported", []string{"-origin", "log.example/log", "-url", "https://example.com/archive"}, 0, "  SKIP:"},
		{"missing args", nil, 2, "Usage:"},
		{"missing origin", []string{"-url", "https://archive.org/details/base"}, 2, "Usage:"},
		{"missing URL", []string{"-origin", "log.example/log"}, 2, "Usage:"},
		{"extra arg", []string{"-origin", "log.example/log", "-url", "https://archive.org/details/base", "extra"}, 2, "Usage:"},
		{"unknown flag", []string{"-unknown"}, 2, "flag provided but not defined"},
		{"help", []string{"-h"}, 0, "-torrent"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			f := newFixture()
			var out bytes.Buffer
			if got := run(f.client(t), tt.args, &out); got != tt.status {
				t.Fatalf("exit %d, want %d: %s", got, tt.status, &out)
			}
			if !strings.Contains(out.String(), tt.want) {
				t.Fatalf("output missing %q: %s", tt.want, &out)
			}
		})
	}
}

func TestRunTorrentURL(t *testing.T) {
	f := newFixture()
	f.responses["/custom.torrent"] = torrent(t, map[string]any{"name": "000.zip"})
	var out bytes.Buffer
	args := []string{"-origin", f.entry.origin, "-url", f.entry.location, "-torrent", "https://archive.org/custom.torrent"}
	if got := run(f.client(t), args, &out); got != 0 {
		t.Fatalf("exit %d: %s", got, &out)
	}
	found := false
	for _, path := range f.requests {
		if path == "/custom.torrent" {
			found = true
		}
	}
	if !found {
		t.Fatal("supplied torrent URL was not fetched")
	}
}
