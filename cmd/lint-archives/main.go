// Command lint-archives checks the archived logs listed in README.md.
// Currently only Internet Archive locations are supported.
package main

import (
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

type entry struct {
	origin     string
	location   string
	hasTorrent bool
}

// extractEntries reads the repository's simple Markdown table format, including
// rows with an omitted torrent cell. It is not a general Markdown parser.
func extractEntries(content string) []entry {
	var entries []entry
	for line := range strings.SplitSeq(content, "\n") {
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
		entries = append(entries, entry{
			origin:     origin,
			location:   strings.TrimSpace(cells[2]),
			hasTorrent: strings.Contains(cells[3], ".torrent"),
		})
	}
	return entries
}

func lintEntries(client *http.Client, entries []entry, out io.Writer) bool {
	fmt.Fprintf(out, "Found %d archive entries\n", len(entries))
	passed, skipped := true, 0
	for _, e := range entries {
		fmt.Fprintf(out, "\nLinting %s (%s)...\n", e.location, e.origin)
		var errors []string
		switch {
		// Match anywhere so malformed formatting around IA links still gets checked.
		case strings.Contains(e.location, "https://archive.org/details/"):
			errors = lintIA(client, e)
		default:
			fmt.Fprintln(out, "  SKIP: archive location not yet supported")
			skipped++
			continue
		}
		if len(errors) == 0 {
			fmt.Fprintln(out, "  OK")
		}
		for _, err := range errors {
			passed = false
			fmt.Fprintf(out, "  ERROR: %s\n", err)
		}
	}
	if passed {
		fmt.Fprintln(out, "\nAll checks passed!")
	} else {
		fmt.Fprintln(out, "\nLinting failed!")
	}
	if skipped != 0 {
		fmt.Fprintf(out, "%d unsupported entries skipped.\n", skipped)
	}
	return passed
}

func main() {
	readme := flag.String("readme", "README.md", "path to the archive directory's README")
	flag.Parse()
	if flag.NArg() != 0 {
		flag.Usage()
		os.Exit(2)
	}
	content, err := os.ReadFile(*readme)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if !lintEntries(&http.Client{Timeout: 30 * time.Second}, extractEntries(string(content)), os.Stdout) {
		os.Exit(1)
	}
}
