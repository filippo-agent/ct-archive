// Public-endpoint-only TLS probe: never sends HTTP data or credentials.
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"time"
)

var host = flag.String("host", "dn760103.eu.archive.org", "TLS SNI and DNS name")
var ip = flag.String("ip", "", "pin address; otherwise resolve once")
var out = flag.String("out", "artifacts", "output directory")
var rounds = flag.Int("rounds", 2, "interleaved repetitions")
var modes = flag.String("modes", "full-default,full-classic,raw-default,raw-classic,raw-classic-pad,full-default-mss900,full-default-recordsplit,raw-default-removehybrid", "ordered comma-separated variants")

func u16(p []byte) int      { return int(binary.BigEndian.Uint16(p)) }
func put16(p []byte, n int) { binary.BigEndian.PutUint16(p, uint16(n)) }
func put24(p []byte, n int) { p[0] = byte(n >> 16); p[1] = byte(n >> 8); p[2] = byte(n) }
func extensionOffset(p []byte) int {
	i := 9 + 2 + 32
	i += 1 + int(p[i])
	i += 2 + u16(p[i:])
	i += 1 + int(p[i])
	return i
}

// Raw first-flight mutations cannot complete a Go handshake (transcript differs).
// They can still establish whether the server receives and responds to this CH.
func mutate(p []byte, mode string, target int) []byte {
	p = bytes.Clone(p)
	off := extensionOffset(p)
	if mode == "pad" {
		n := target - len(p) - 4
		if n < 0 {
			panic("padding too short")
		}
		ext := make([]byte, n+4)
		put16(ext, 21)
		put16(ext[2:], n)
		p = append(p, ext...)
	}
	if mode == "removehybrid" {
		for i := off + 2; i < len(p); {
			t, n := u16(p[i:]), u16(p[i+2:])
			if t == 51 {
				data := p[i+4 : i+4+n]
				kept := []byte{0, 0}
				for j := 2; j < len(data); {
					l := u16(data[j+2:])
					if u16(data[j:]) != int(tls.X25519MLKEM768) {
						kept = append(kept, data[j:j+4+l]...)
					}
					j += 4 + l
				}
				put16(kept, len(kept)-2)
				ext := make([]byte, 4)
				put16(ext, 51)
				put16(ext[2:], len(kept))
				ext = append(ext, kept...)
				p = append(append(p[:i:i], ext...), p[i+4+n:]...)
				break
			}
			i += 4 + n
		}
	}
	put16(p[3:], len(p)-5)
	put24(p[6:], len(p)-9)
	put16(p[off:], len(p)-off-2)
	return p
}

type event struct {
	At    string `json:"at"`
	Op    string `json:"op"`
	N     int    `json:"n"`
	Error string `json:"error,omitempty"`
}
type wire struct {
	net.Conn
	prefix  string
	events  *json.Encoder
	first   bool
	split   bool
	written int
	read    int
}

func (w *wire) log(op string, n int, err error) {
	e := event{At: time.Now().UTC().Format(time.RFC3339Nano), Op: op, N: n}
	if err != nil {
		e.Error = err.Error()
	}
	w.events.Encode(e)
}
func (w *wire) Write(p []byte) (int, error) {
	if w.first {
		w.first = false
		os.WriteFile(w.prefix+"-clienthello.bin", p, 0644)
		if w.split {
			body := p[5:]
			var records []byte
			for len(body) > 0 {
				n := 512
				if n > len(body) {
					n = len(body)
				}
				hdr := bytes.Clone(p[:5])
				put16(hdr[3:], n)
				records = append(records, hdr...)
				records = append(records, body[:n]...)
				body = body[n:]
			}
			n, err := w.Conn.Write(records)
			w.log("write-recordsplit", n, err)
			if err != nil {
				return 0, err
			}
			return len(p), nil
		}
	}
	n, err := w.Conn.Write(p)
	w.written += n
	w.log("write", n, err)
	return n, err
}
func (w *wire) Read(p []byte) (int, error) {
	n, err := w.Conn.Read(p)
	if n > 0 {
		f, _ := os.OpenFile(w.prefix+"-received.bin", os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
		f.Write(p[:n])
		f.Close()
	}
	w.read += n
	w.log("read", n, err)
	return n, err
}

type dummy struct{ p []byte }

func (d *dummy) Write(p []byte) (int, error) {
	d.p = bytes.Clone(p)
	return 0, errors.New("capture only")
}
func (d *dummy) Read([]byte) (int, error)         { return 0, io.EOF }
func (d *dummy) Close() error                     { return nil }
func (d *dummy) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (d *dummy) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (d *dummy) SetDeadline(time.Time) error      { return nil }
func (d *dummy) SetReadDeadline(time.Time) error  { return nil }
func (d *dummy) SetWriteDeadline(time.Time) error { return nil }
func config(classic bool) *tls.Config {
	c := &tls.Config{ServerName: *host, NextProtos: []string{"h2", "http/1.1"}}
	if classic {
		c.CurvePreferences = []tls.CurveID{tls.X25519, tls.CurveP256, tls.CurveP384, tls.CurveP521}
	}
	return c
}
func hello(classic bool) []byte {
	d := new(dummy)
	tls.Client(d, config(classic)).Handshake()
	return d.p
}
func main() {
	flag.Parse()
	os.MkdirAll(*out, 0755)
	if *ip == "" {
		ips, err := net.LookupIP(*host)
		if err != nil {
			panic(err)
		}
		fmt.Printf("DNS %s %v\n", *host, ips)
		for _, a := range ips {
			if a.To4() != nil {
				*ip = a.String()
				break
			}
		}
	}
	if *ip == "" {
		panic("no IPv4")
	}
	fmt.Printf("PIN %s %s default_record=%d classic_record=%d GODEBUG=%s\n", *host, *ip, len(hello(false)), len(hello(true)), os.Getenv("GODEBUG"))
	summary, _ := os.Create(filepath.Join(*out, "results.jsonl"))
	defer summary.Close()
	enc := json.NewEncoder(io.MultiWriter(os.Stdout, summary))
	for round := 0; round < *rounds; round++ {
		order := strings.Split(*modes, ",")
		if round%2 == 1 {
			for i, j := 0, len(order)-1; i < j; i, j = i+1, j-1 {
				order[i], order[j] = order[j], order[i]
			}
		}
		for _, mode := range order {
			name := fmt.Sprintf("r%d-%s", round, mode)
			prefix := filepath.Join(*out, name)
			events, _ := os.Create(prefix + "-events.jsonl")
			keys, _ := os.Create(prefix + "-keylog.txt")
			c := config(strings.Contains(mode, "classic"))
			c.KeyLogWriter = keys
			dialer := net.Dialer{Timeout: 8 * time.Second}
			if strings.Contains(mode, "mss900") {
				dialer.Control = func(network, address string, rc syscall.RawConn) error {
					var e error
					rc.Control(func(fd uintptr) { e = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, syscall.TCP_MAXSEG, 900) })
					return e
				}
			}
			start := time.Now()
			conn, err := dialer.DialContext(context.Background(), "tcp4", net.JoinHostPort(*ip, "443"))
			res := map[string]any{"name": name, "mode": mode, "host": *host, "ip": *ip, "start": start.UTC().Format(time.RFC3339Nano)}
			if err == nil {
				res["local"] = conn.LocalAddr().String()
				res["remote"] = conn.RemoteAddr().String()
				res["tcp_ms"] = time.Since(start).Milliseconds()
				conn.SetDeadline(start.Add(10 * time.Second))
				w := &wire{Conn: conn, prefix: prefix, events: json.NewEncoder(events), first: true, split: strings.Contains(mode, "recordsplit")}
				if strings.HasPrefix(mode, "raw-") {
					p := hello(strings.Contains(mode, "classic"))
					if strings.Contains(mode, "pad") {
						p = mutate(p, "pad", len(hello(false)))
					}
					if strings.Contains(mode, "removehybrid") {
						p = mutate(p, "removehybrid", 0)
					}
					_, err = w.Write(p)
					res["clienthello_bytes"] = len(p)
					if err == nil {
						hdr := make([]byte, 5)
						_, err = io.ReadFull(w, hdr)
						if err == nil {
							res["first_record_type"] = hdr[0]
							res["first_record_bytes"] = u16(hdr[3:])
							body := make([]byte, u16(hdr[3:]))
							_, err = io.ReadFull(w, body)
							res["first_record_hex"] = fmt.Sprintf("%x", body)
						}
					}
				} else {
					tc := tls.Client(w, c)
					err = tc.Handshake()
					if err == nil {
						s := tc.ConnectionState()
						res["tls_version"] = s.Version
						res["cipher"] = tls.CipherSuiteName(s.CipherSuite)
						res["alpn"] = s.NegotiatedProtocol
						if v := reflect.ValueOf(s).FieldByName("CurveID"); v.IsValid() {
							res["curve"] = fmt.Sprint(v.Interface())
						}
					}
				}
				res["read_bytes"] = w.read
				res["written_bytes"] = w.written
				conn.Close()
			}
			if err != nil {
				res["error"] = err.Error()
			}
			res["elapsed_ms"] = time.Since(start).Milliseconds()
			enc.Encode(res)
			events.Close()
			keys.Close()
			time.Sleep(200 * time.Millisecond)
		}
	}
}
