// A handshake alone reproduces the failure: no HTTP, redirects, or downloads.
// Compare identical binary with GODEBUG= and GODEBUG=tlsmlkem=0.
package main

import (
	"crypto/tls"
	"fmt"
	"net"
	"time"
)

func main() {
	start := time.Now()
	c, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second},
		"tcp4", "145.116.0.213:443",
		&tls.Config{ServerName: "dn760103.eu.archive.org"})
	if c != nil {
		fmt.Printf("version=%x curve=%v cipher=%s\n", c.ConnectionState().Version,
			c.ConnectionState().CurveID, tls.CipherSuiteName(c.ConnectionState().CipherSuite))
		c.Close()
	}
	fmt.Printf("elapsed=%v error=%v\n", time.Since(start), err)
}
