// Command lint-archives checks a single archived Certificate Transparency log.
// Currently only Internet Archive locations are supported.
package main

import (
	"flag"
	"fmt"
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

func main() {
	var e entry
	flag.StringVar(&e.origin, "origin", "", "log origin (required)")
	flag.StringVar(&e.location, "url", "", "archive URL (required; quote space-separated URLs for split IA items)")
	flag.StringVar(&e.torrentURL, "torrent", "", "torrent URL (optional; for the base item of a split IA archive)")
	flag.Parse()
	if flag.NArg() != 0 || e.origin == "" || e.location == "" {
		flag.Usage()
		os.Exit(2)
	}
	fmt.Printf("Linting %s (%s)...\n", e.location, e.origin)
	var errors []string
	switch {
	// Match anywhere so malformed formatting around IA links still gets checked.
	case strings.Contains(e.location, "https://archive.org/details/"):
		errors = lintIA(&http.Client{Timeout: 30 * time.Second}, e)
	default:
		fmt.Println("  SKIP: archive location not yet supported")
		return
	}
	for _, err := range errors {
		fmt.Printf("  ERROR: %s\n", err)
	}
	if len(errors) != 0 {
		os.Exit(1)
	}
	fmt.Println("  OK")
}
