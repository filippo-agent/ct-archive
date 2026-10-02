// Linux reproducer. No HTTP, torrent, redirect, or concurrent requests required.
package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"net"
	"syscall"
	"time"
)

func main() {
	host := flag.String("host", "dn760103.eu.archive.org", "SNI hostname")
	addr := flag.String("addr", "145.116.0.213:443", "pinned destination")
	mss := flag.Int("mss", 0, "TCP_MAXSEG before connect; 0 leaves default")
	flag.Parse()
	d := net.Dialer{Timeout: 5 * time.Second}
	if *mss != 0 {
		d.Control = func(_, _ string, r syscall.RawConn) error {
			var err error
			if e := r.Control(func(fd uintptr) { err = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, syscall.TCP_MAXSEG, *mss) }); e != nil {
				return e
			}
			return err
		}
	}
	c, err := d.DialContext(context.Background(), "tcp4", *addr)
	if err != nil {
		panic(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(10 * time.Second))
	t := tls.Client(c, &tls.Config{ServerName: *host})
	start := time.Now()
	err = t.Handshake()
	s := t.ConnectionState()
	fmt.Printf("local=%s remote=%s elapsed=%v complete=%v curve=%v err=%v\n", c.LocalAddr(), c.RemoteAddr(), time.Since(start), s.HandshakeComplete, s.CurveID, err)
}
