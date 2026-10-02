// Command lint-archives checks a single archived Certificate Transparency log.
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
	torrentURL string
}

func run(client *http.Client, args []string, out io.Writer) int {
	flags := flag.NewFlagSet("lint-archives", flag.ContinueOnError)
	flags.SetOutput(out)
	var e entry
	flags.StringVar(&e.origin, "origin", "", "log origin (required)")
	flags.StringVar(&e.location, "url", "", "archive URL (required; quote space-separated URLs for split IA items)")
	flags.StringVar(&e.torrentURL, "torrent", "", "torrent URL (optional; for the base item of a split IA archive)")
	if err := flags.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}
	if flags.NArg() != 0 || e.origin == "" || e.location == "" {
		fmt.Fprintln(out, "Usage: lint-archives -origin ORIGIN -url URL [-torrent URL]")
		flags.PrintDefaults()
		return 2
	}
	fmt.Fprintf(out, "Linting %s (%s)...\n", e.location, e.origin)
	var errors []string
	switch {
	// Match anywhere so malformed formatting around IA links still gets checked.
	case strings.Contains(e.location, "https://archive.org/details/"):
		errors = lintIA(client, e)
	default:
		fmt.Fprintln(out, "  SKIP: archive location not yet supported")
		return 0
	}
	for _, err := range errors {
		fmt.Fprintf(out, "  ERROR: %s\n", err)
	}
	if len(errors) != 0 {
		return 1
	}
	fmt.Fprintln(out, "  OK")
	return 0
}

func main() {
	os.Exit(run(&http.Client{Timeout: 30 * time.Second}, os.Args[1:], os.Stdout))
}
