package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/anacrolix/torrent/bencode"
)

type fixture struct {
	entry      entry
	metadata   map[string]any
	files      []map[string]string
	log        map[string]string
	checkpoint string
	responses  map[string]string
	requests   []string
}

func newFixture() *fixture {
	return &fixture{
		entry:      entry{origin: "log.example/log", location: "https://archive.org/details/base"},
		metadata:   map[string]any{"subject": "certificate transparency log", "collection": "datasets", "ctlogid": "log-id", "cturl": "https://log.example/log/", "ctlogsize": "1"},
		files:      []map[string]string{{"name": "000.zip", "source": "original"}},
		log:        map[string]string{"log_id": "log-id", "url": "https://log.example/log"},
		checkpoint: "log.example/log\n1\nhash\n",
		responses:  make(map[string]string),
	}
}

func jsonText(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return string(b)
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func (f *fixture) client(t *testing.T) *http.Client {
	t.Helper()
	defaults := map[string]string{
		"/metadata/base":                     jsonText(map[string]any{"metadata": f.metadata, "files": f.files}),
		"/download/base/000.zip/log.v3.json": jsonText(f.log),
		"/download/base/000.zip/checkpoint":  f.checkpoint,
	}
	for path, body := range defaults {
		if _, ok := f.responses[path]; !ok {
			f.responses[path] = body
		}
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.requests = append(f.requests, r.URL.Path)
		body, ok := f.responses[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		fmt.Fprint(w, body)
	}))
	t.Cleanup(server.Close)
	target, _ := url.Parse(server.URL)
	transport := server.Client().Transport
	return &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Host != "archive.org" {
			t.Errorf("unexpected host: %s", r.URL.Host)
		}
		r = r.Clone(r.Context())
		r.URL.Scheme, r.URL.Host = target.Scheme, target.Host
		return transport.RoundTrip(r)
	})}
}

func TestLintIA(t *testing.T) {
	tests := []struct {
		name   string
		change func(*fixture)
		want   string
	}{
		{"valid", func(f *fixture) {}, ""},
		{"dagger", func(f *fixture) { f.entry.location += " †" }, ""},
		{"lists", func(f *fixture) {
			f.metadata["subject"] = []string{"other", "certificate transparency log"}
			f.metadata["collection"] = []string{"other", "datasets_unsorted"}
		}, ""},
		{"numeric size", func(f *fixture) { f.metadata["ctlogsize"] = 1 }, ""},
		{"static", func(f *fixture) {
			delete(f.metadata, "cturl")
			f.metadata["ctsubmissionurl"] = "https://log.example/log/"
			f.metadata["ctmonitoringurl"] = "https://monitor.example/"
			delete(f.log, "url")
			f.log["submission_url"] = "https://log.example/log"
			f.log["monitoring_url"] = "https://monitor.example"
		}, ""},
		{"missing metadata", func(f *fixture) { f.responses["/metadata/base"] = `{}` }, "not found or has no metadata"},
		{"metadata JSON", func(f *fixture) { f.responses["/metadata/base"] = `{` }, "base:"},
		{"location", func(f *fixture) { f.entry.location += " unexpected" }, "Archive location should be"},
		{"topic", func(f *fixture) { f.metadata["subject"] = "other" }, "Missing 'certificate transparency log' topic"},
		{"id", func(f *fixture) { delete(f.metadata, "ctlogid") }, "Missing 'ctlogid' metadata"},
		{"URL", func(f *fixture) {
			delete(f.metadata, "cturl")
			f.metadata["ctsubmissionurl"] = "https://log.example/log"
		}, "Missing URL metadata"},
		{"collection", func(f *fixture) { f.metadata["collection"] = []string{"other"} }, "Collection should be"},
		{"size", func(f *fixture) { delete(f.metadata, "ctlogsize") }, "Missing 'ctlogsize' metadata"},
		{"invalid size", func(f *fixture) { f.metadata["ctlogsize"] = "invalid" }, "Invalid ctlogsize value"},
		{"zip count", func(f *fixture) { f.metadata["ctlogsize"] = "16777217" }, "Expected 2 zip files"},
		{"exact zip boundary", func(f *fixture) { f.metadata["ctlogsize"] = "16777216"; f.checkpoint = "log.example/log\n16777216\n" }, ""},
		{"missing zips", func(f *fixture) { f.files = nil }, "No zip files found"},
		{"missing base zip", func(f *fixture) { f.files[0]["name"] = "001.zip" }, "No 000.zip found"},
		{"log id", func(f *fixture) { f.log["log_id"] = "wrong" }, "does not match metadata ctlogid"},
		{"log URL", func(f *fixture) { f.log["url"] = "https://wrong.example" }, "does not match metadata cturl"},
		{"static submission", func(f *fixture) {
			delete(f.metadata, "cturl")
			f.metadata["ctsubmissionurl"] = "https://log.example/log"
			f.metadata["ctmonitoringurl"] = "https://monitor.example"
		}, "does not match metadata ctsubmissionurl"},
		{"static monitoring", func(f *fixture) {
			delete(f.metadata, "cturl")
			f.metadata["ctsubmissionurl"] = "https://log.example/log"
			f.metadata["ctmonitoringurl"] = "https://monitor.example"
			f.log["submission_url"] = "https://log.example/log"
		}, "does not match metadata ctmonitoringurl"},
		{"log JSON", func(f *fixture) { f.responses["/download/base/000.zip/log.v3.json"] = `{` }, "Invalid JSON in log.v3.json"},
		{"checkpoint origin", func(f *fixture) { f.checkpoint = "wrong\n1\n" }, "does not match URL metadata"},
		{"checkpoint size", func(f *fixture) { f.checkpoint = "log.example/log\n2\n" }, "does not match ctlogsize"},
		{"checkpoint invalid size", func(f *fixture) { f.checkpoint = "log.example/log\ninvalid\n" }, "Invalid checkpoint size"},
		{"checkpoint format", func(f *fixture) { f.checkpoint = "one line" }, "Invalid checkpoint format"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFixture()
			tt.change(f)
			got := lintIA(f.client(t), f.entry)
			if tt.want == "" {
				if len(got) != 0 {
					t.Fatalf("unexpected errors: %v", got)
				}
			} else if !strings.Contains(strings.Join(got, "\n"), tt.want) {
				t.Fatalf("got %v, want %q", got, tt.want)
			}
		})
	}
}

func TestLintIASplit(t *testing.T) {
	f := newFixture()
	f.entry.location += " https://archive.org/details/base_ext1"
	f.entry.hasTorrent = true
	f.metadata["ctlogsize"] = "16777217"
	f.checkpoint = "log.example/log\n16777217\n"
	f.responses["/metadata/base_ext1"] = jsonText(map[string]any{"metadata": f.metadata, "files": []map[string]string{{"name": "001.zip", "source": "original"}}})
	f.responses["/download/base_ext1/001.zip/log.v3.json"] = jsonText(f.log)
	f.responses["/download/base_ext1/001.zip/checkpoint"] = f.checkpoint
	f.responses["/download/base/base_archive.torrent"] = torrent(t, map[string]any{"name": "000.zip"})
	if got := lintIA(f.client(t), f.entry); len(got) != 0 {
		t.Fatalf("unexpected errors: %v", got)
	}
	for _, path := range f.requests {
		if strings.Contains(path, "ext1_archive.torrent") {
			t.Fatal("extension torrent must not be checked")
		}
	}
}

func torrent(t *testing.T, info map[string]any) string {
	t.Helper()
	b, err := bencode.Marshal(map[string]any{"info": info})
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestLintIATorrent(t *testing.T) {
	for _, mode := range []string{"single", "multi", "missing", "invalid", "HTTP", "skip"} {
		t.Run(mode, func(t *testing.T) {
			f := newFixture()
			f.entry.hasTorrent = mode != "skip"
			f.files = append(f.files, map[string]string{"name": "base_files.xml", "source": "original"}, map[string]string{"name": "derived.txt", "source": "derivative"})
			switch mode {
			case "single", "skip":
				f.responses["/download/base/base_archive.torrent"] = torrent(t, map[string]any{"name": "000.zip"})
			case "multi":
				f.files = append(f.files, map[string]string{"name": "dir/file", "source": "original"})
				f.responses["/download/base/base_archive.torrent"] = torrent(t, map[string]any{"name": "base", "files": []any{map[string]any{"path": []string{"000.zip"}}, map[string]any{"path": []string{"dir", "file"}}}})
			case "missing":
				f.responses["/download/base/base_archive.torrent"] = torrent(t, map[string]any{"name": "other.zip"})
			case "invalid":
				f.responses["/download/base/base_archive.torrent"] = "not bencode"
			}
			got := lintIA(f.client(t), f.entry)
			want := map[string]string{"missing": "Torrent is missing 1 files: 000.zip", "invalid": "Failed to parse torrent", "HTTP": "Failed to fetch torrent: HTTP 404"}[mode]
			if want == "" {
				if len(got) != 0 {
					t.Fatalf("unexpected errors: %v", got)
				}
			} else if !strings.Contains(strings.Join(got, "\n"), want) {
				t.Fatalf("got %v, want %q", got, want)
			}
			if mode == "skip" {
				for _, path := range f.requests {
					if strings.HasSuffix(path, ".torrent") {
						t.Fatal("unexpected torrent request")
					}
				}
			}
		})
	}
}

func TestLintIAExtensionNames(t *testing.T) {
	for _, suffix := range []string{"ext0", "ext2", "other"} {
		t.Run(suffix, func(t *testing.T) {
			f := newFixture()
			f.entry.location += " https://archive.org/details/base_" + suffix
			f.responses["/metadata/base_"+suffix] = `{}`
			errors := lintIA(f.client(t), f.entry)
			if !strings.Contains(strings.Join(errors, "\n"), "Extension items must be named consecutively") {
				t.Fatalf("missing extension naming error: %v", errors)
			}
		})
	}
}

func TestLintIAFetchErrors(t *testing.T) {
	for _, file := range []string{"log.v3.json", "checkpoint"} {
		t.Run(file, func(t *testing.T) {
			f := newFixture()
			client := f.client(t)
			delete(f.responses, "/download/base/000.zip/"+file)
			got := lintIA(client, f.entry)
			want := "Failed to fetch " + file + ": HTTP 404"
			if !strings.Contains(strings.Join(got, "\n"), want) {
				t.Fatalf("got %v, want %q", got, want)
			}
		})
	}
	t.Run("network", func(t *testing.T) {
		client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return nil, fmt.Errorf("network unavailable")
		})}
		got := lintIA(client, newFixture().entry)
		if !strings.Contains(strings.Join(got, "\n"), "Failed to fetch metadata:") {
			t.Fatalf("unexpected errors: %v", got)
		}
	})
}
