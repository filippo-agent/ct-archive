package main

import (
	"bytes"
	"net/http"
	"reflect"
	"strings"
	"testing"
)

func TestExtractEntries(t *testing.T) {
	input := `# Archives
| Log Origin | Archive Location | |
|------------|------------------|--|
| base | https://archive.org/details/base † | [.torrent](base.torrent) |
| split | https://archive.org/details/split https://archive.org/details/split_ext1 |
| other | https://example.com/archive/ ||
| torrent-only | *too large for the Internet Archive* | [.torrent](local.torrent) |
Not a table row
`
	want := []entry{
		{"base", "https://archive.org/details/base †", true},
		{"split", "https://archive.org/details/split https://archive.org/details/split_ext1", false},
		{"other", "https://example.com/archive/", false},
		{"torrent-only", "*too large for the Internet Archive*", true},
	}
	if got := extractEntries(input); !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v, want %#v", got, want)
	}
}

func TestLintEntries(t *testing.T) {
	f := newFixture()
	f.responses["/metadata/bad"] = `{}`
	client := f.client(t)
	var out bytes.Buffer
	entries := []entry{
		{origin: "bad", location: "https://archive.org/details/bad"},
		{origin: "unsupported", location: "https://example.com/archive/"},
		f.entry,
	}
	if lintEntries(client, entries, &out) {
		t.Fatal("expected lint failure")
	}
	for _, want := range []string{"Found 3 archive entries", "ERROR:", "SKIP:", "  OK", "Linting failed!", "1 unsupported entries skipped."} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("output missing %q: %s", want, &out)
		}
	}
	out.Reset()
	if !lintEntries(&http.Client{}, entries[1:2], &out) {
		t.Fatal("unsupported hosts should remain skipped in this port")
	}
}
