#!/usr/bin/env python3
"""Minimal fake-response honeypot for testing P24 (honeypot-detect.nse).

Opens many TCP listeners on localhost and returns the SAME banner on every one,
emulating the classic honeypot/tarpit signature (lots of "open" ports, uniform
banners). Binds localhost only.

Usage: honeypot.py <start_port> <count> [banner]
"""
import select
import socket
import sys

start = int(sys.argv[1]) if len(sys.argv) > 1 else 9000
count = int(sys.argv[2]) if len(sys.argv) > 2 else 40
banner = (sys.argv[3] if len(sys.argv) > 3 else "FakeService 1.0 ready\r\n").encode()

listeners = []
for i in range(count):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", start + i))
    s.listen(16)
    s.setblocking(False)
    listeners.append(s)

print("listening on %d ports %d-%d" % (count, start, start + count - 1), flush=True)

while True:
    r, _, _ = select.select(listeners, [], [], 1.0)
    for s in r:
        try:
            conn, _ = s.accept()
            conn.sendall(banner)
            conn.close()
        except Exception:
            pass
