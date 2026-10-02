#!/usr/bin/env python3
"""No TLS and no Go: a single padded plaintext HTTP write to the public HTTPS port.

The expected application response is nginx's 'plain HTTP request ... HTTPS port'
400. Packet captures distinguish a TCP delivery failure from an application stall.
"""
import argparse
import json
import pathlib
import socket
import struct
import time

p = argparse.ArgumentParser()
p.add_argument("--ip", default="145.116.0.213")
p.add_argument("--sizes", default="1436,1437,1440,1441,1447,1448,1529")
p.add_argument("--out", default="artifacts/tcp-repro.jsonl")
p.add_argument("--rounds", type=int, default=2)
a = p.parse_args()
pathlib.Path(a.out).parent.mkdir(parents=True, exist_ok=True)
with open(a.out, "w") as output:
    for round in range(a.rounds):
        sizes = [int(n) for n in a.sizes.split(",")]
        if round % 2:
            sizes.reverse()
        for n in sizes:
            prefix = b"GET / HTTP/1.0\r\nHost: dn760103.eu.archive.org\r\nX-Padding: "
            data = prefix + b"a" * (n - len(prefix) - 4) + b"\r\n\r\n"
            assert len(data) == n
            s = socket.socket()
            s.settimeout(3)
            t = time.time()
            r = {"round": round, "size": n, "start_unix": t}
            try:
                s.connect((a.ip, 443))
                r["local"] = "%s:%d" % s.getsockname()
                s.sendall(data)
                response = s.recv(4096)
                r["response"] = response.decode(errors="replace")
            except OSError as e:
                r["error"] = str(e)
            finally:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
                s.close()
            r["elapsed_ms"] = int((time.time() - t) * 1000)
            output.write(json.dumps(r) + "\n")
            output.flush()
            print(json.dumps(r), flush=True)
            time.sleep(0.2)
