package main

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"time"
)

var host = flag.String("host", "dn760103.eu.archive.org", "TLS hostname")
var ip = flag.String("ip", "", "pinned destination IP")
var rounds = flag.Int("rounds", 2, "rounds")
var out = flag.String("out", "evidence", "output directory")

func u16(b []byte) int      { return int(binary.BigEndian.Uint16(b)) }
func put16(b []byte, n int) { binary.BigEndian.PutUint16(b, uint16(n)) }
func config(classic bool) *tls.Config {
	c := &tls.Config{ServerName: *host, NextProtos: []string{"h2", "http/1.1"}}
	if classic {
		c.CurvePreferences = []tls.CurveID{tls.X25519, tls.CurveP256, tls.CurveP384, tls.CurveP521}
	}
	return c
}
func hello(classic bool) []byte {
	a, b := net.Pipe()
	defer b.Close()
	go func() { defer a.Close(); tls.Client(a, config(classic)).Handshake() }()
	h := make([]byte, 5)
	if _, e := io.ReadFull(b, h); e != nil {
		panic(e)
	}
	p := make([]byte, u16(h[3:]))
	if _, e := io.ReadFull(b, p); e != nil {
		panic(e)
	}
	return append(h, p...)
}
func padded(b []byte, size int) []byte {
	b = append([]byte(nil), b...)
	// record(5), handshake(4), version(2), random(32), session ID vector,
	// cipher suites vector, compression vector, extensions vector.
	i := 43
	i += 1 + int(b[i])
	i += 2 + u16(b[i:])
	i += 1 + int(b[i])
	n := size - len(b)
	if n < 4 {
		panic("padding too small")
	}
	ext := make([]byte, n)
	put16(ext, 21)
	put16(ext[2:], n-4)
	put16(b[i:], u16(b[i:])+n)
	b = append(b, ext...)
	put16(b[3:], len(b)-5)
	l := len(b) - 9
	b[6] = byte(l >> 16)
	b[7] = byte(l >> 8)
	b[8] = byte(l)
	return b
}

type wrapped struct {
	net.Conn
	split   int
	records bool
	prefix  string
	first   bool
}

func (w *wrapped) Write(b []byte) (int, error) {
	if !w.first {
		return w.Conn.Write(b)
	}
	w.first = false
	os.WriteFile(w.prefix+"-sent.bin", b, 0644)
	fmt.Printf("  write=%d first=%s\n", len(b), hex.EncodeToString(b[:min(9, len(b))]))
	if w.records {
		payload := b[5:]
		var wire []byte
		for len(payload) > 0 {
			n := min(600, len(payload))
			h := append([]byte(nil), b[:5]...)
			put16(h[3:], n)
			wire = append(wire, h...)
			wire = append(wire, payload[:n]...)
			payload = payload[n:]
		}
		_, e := w.Conn.Write(wire)
		return len(b), e
	}
	if w.split > 0 {
		for off := 0; off < len(b); {
			n := min(w.split, len(b)-off)
			k, e := w.Conn.Write(b[off : off+n])
			off += k
			if e != nil {
				return off, e
			}
			if off < len(b) {
				time.Sleep(100 * time.Millisecond)
			}
		}
		return len(b), nil
	}
	return w.Conn.Write(b)
}
func dial(mss int) (net.Conn, error) {
	d := net.Dialer{Timeout: 5 * time.Second}
	if mss > 0 {
		d.Control = func(_, _ string, c syscall.RawConn) error {
			var e error
			c.Control(func(fd uintptr) { e = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, syscall.TCP_MAXSEG, mss) })
			return e
		}
	}
	return d.DialContext(context.Background(), "tcp4", net.JoinHostPort(*ip, "443"))
}
func main() {
	flag.Parse()
	os.MkdirAll(*out, 0755)
	if *ip == "" {
		a, e := net.LookupIP(*host)
		if e != nil {
			panic(e)
		}
		for _, v := range a {
			if v.To4() != nil {
				*ip = v.String()
				break
			}
		}
	}
	fmt.Printf("go=%s host=%s ip=%s GODEBUG=%s\n", runtime.Version(), *host, *ip, os.Getenv("GODEBUG"))
	for r := 0; r < *rounds; r++ {
		def, cl := hello(false), hello(true)
		os.WriteFile(filepath.Join(*out, fmt.Sprintf("hello-default-%d.bin", r)), def, 0644)
		fmt.Printf("hello sizes default=%d classic=%d\n", len(def), len(cl))
		variants := []struct {
			name       string
			classic    bool
			split, mss int
			records    bool
			raw        []byte
		}{
			{name: "default"}, {name: "classic", classic: true},
			{name: "classic-padded", raw: padded(cl, len(def))},
			{name: "default-split600", split: 600},
			{name: "default-record600", records: true},
			{name: "default-mss600", mss: 600},
			{name: "classic-padded2000", raw: padded(cl, 2000)},
			{name: "default-again"}, {name: "classic-again", classic: true},
		}
		for _, v := range variants {
			label := fmt.Sprintf("r%d-%s", r, v.name)
			prefix := filepath.Join(*out, label)
			start := time.Now()
			c, e := dial(v.mss)
			if e != nil {
				fmt.Printf("%s dial error=%v\n", label, e)
				continue
			}
			c.SetDeadline(time.Now().Add(10 * time.Second))
			fmt.Printf("%s start=%s local=%s remote=%s\n", label, start.UTC().Format(time.RFC3339Nano), c.LocalAddr(), c.RemoteAddr())
			w := &wrapped{Conn: c, first: true, split: v.split, records: v.records, prefix: prefix}
			if v.raw != nil {
				_, e = w.Write(v.raw)
				if e == nil {
					buf := make([]byte, 16384)
					var n int
					n, e = c.Read(buf)
					os.WriteFile(prefix+"-recv.bin", buf[:n], 0644)
					fmt.Printf("  raw read=%d first=%s\n", n, hex.EncodeToString(buf[:min(16, n)]))
				}
			} else {
				cfg := config(v.classic)
				keys, _ := os.Create(prefix + "-keys.log")
				cfg.KeyLogWriter = keys
				tc := tls.Client(w, cfg)
				e = tc.Handshake()
				s := tc.ConnectionState()
				fmt.Printf("  complete=%v version=%04x cipher=%04x alpn=%s\n", s.HandshakeComplete, s.Version, s.CipherSuite, s.NegotiatedProtocol)
				keys.Close()
			}
			fmt.Printf("%s elapsed=%v error=%v\n", label, time.Since(start), e)
			c.Close()
			time.Sleep(250 * time.Millisecond)
		}
	}
}
