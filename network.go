package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"time"
)

func networkSuite() {
	cl := hello(true)
	type variant struct {
		name       string
		raw        []byte
		mss, split int
		post       bool
	}
	vs := []variant{}
	for _, n := range []int{1200, 1300, 1350, 1400, 1420, 1430, 1440, 1448, 1449, 1500, 1529} {
		vs = append(vs, variant{name: fmt.Sprintf("pad%d", n), raw: padded(cl, n)})
	}
	for _, n := range []int{1300, 1400, 1420, 1440, 1460} {
		vs = append(vs, variant{name: fmt.Sprintf("default-mss%d", n), mss: n})
	}
	vs = append(vs, variant{name: "post-classic-large", post: true}, variant{name: "post-classic-large-split", post: true, split: 600})
	for _, v := range vs {
		start := time.Now()
		c, e := dial(v.mss)
		if e != nil {
			fmt.Println(v.name, e)
			continue
		}
		c.SetDeadline(time.Now().Add(4 * time.Second))
		if tc, ok := c.(*net.TCPConn); ok {
			defer tc.Close()
		}
		prefix := filepath.Join(*out, v.name)
		fmt.Printf("%s start=%s local=%s remote=%s\n", v.name, start.UTC().Format(time.RFC3339Nano), c.LocalAddr(), c.RemoteAddr())
		w := &wrapped{Conn: c, first: true, prefix: prefix}
		if v.raw != nil {
			_, e = w.Write(v.raw)
			if e == nil {
				buf := make([]byte, 16384)
				var n int
				n, e = c.Read(buf)
				os.WriteFile(prefix+"-recv.bin", buf[:n], 0644)
				fmt.Printf("  read=%d\n", n)
			}
		} else {
			cfg := config(v.post)
			if v.post {
				cfg.NextProtos = []string{"http/1.1"}
			}
			keys, _ := os.Create(prefix + "-keys.log")
			cfg.KeyLogWriter = keys
			tc := tls.Client(w, cfg)
			e = tc.Handshake()
			s := tc.ConnectionState()
			fmt.Printf("  complete=%v curve=%v\n", s.HandshakeComplete, s.CurveID)
			if e == nil && v.post {
				// Exercise large client packets after a small classical handshake. No download.
				w.first = true
				w.split = v.split
				w.prefix = prefix + "-http"
				req := fmt.Sprintf("HEAD / HTTP/1.1\r\nHost: %s\r\nX-Probe-Padding: %s\r\nConnection: close\r\n\r\n", *host, string(makeASCII(1800)))
				_, e = io.WriteString(tc, req)
				if e == nil {
					buf := make([]byte, 4096)
					var n int
					n, e = tc.Read(buf)
					fmt.Printf("  HTTP read=%d text=%q\n", n, buf[:min(n, 150)])
				}
			}
			keys.Close()
		}
		fmt.Printf("%s elapsed=%v error=%v\n", v.name, time.Since(start), e)
		// Avoid orphaned retransmissions after a timeout in this measurement suite.
		if tc, ok := c.(*net.TCPConn); ok {
			tc.SetLinger(0)
		}
		c.Close()
		time.Sleep(100 * time.Millisecond)
	}
}
func makeASCII(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = 'a'
	}
	return b
}
