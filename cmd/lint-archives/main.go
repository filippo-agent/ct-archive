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
	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: lint-archives -origin ORIGIN -url URL [-torrent URL]")
		flag.PrintDefaults()
	}
	var e entry
	flag.StringVar(&e.origin, "origin", "", "log origin")
	flag.StringVar(&e.location, "url", "", "archive URL or space-separated URLs")
	flag.StringVar(&e.torrentURL, "torrent", "", "torrent URL (optional)")
	flag.Parse()
	if flag.NArg() != 0 || e.origin == "" || e.location == "" {
		flag.Usage()
		os.Exit(2)
	}
	var errors []string
	switch {
	// Match anywhere so malformed formatting around IA links still gets checked.
	case strings.Contains(e.location, "https://archive.org/details/"):
		errors = lintIA(&http.Client{Timeout: 30 * time.Second}, e)
	default:
		fmt.Printf("SKIP %s: archive host not yet supported\n", e.origin)
		return
	}
	if len(errors) != 0 {
		fmt.Printf("FAIL %s\n", e.origin)
		for _, err := range errors {
			fmt.Printf("  %s\n", err)
		}
		os.Exit(1)
	}
	fmt.Printf("OK   %s\n", e.origin)
}
