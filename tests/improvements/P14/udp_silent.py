#!/usr/bin/env python3
"""Lab UDP service that receives datagrams but never replies. To a UDP scan this
appears open|filtered via 'no-response' (the state is inferred from silence),
which is the low-reliability case P14 must score down. Binds localhost only."""
import socket
import sys

port = int(sys.argv[1]) if len(sys.argv) > 1 else 9876
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("127.0.0.1", port))
while True:
    try:
        s.recvfrom(4096)
    except Exception:
        pass
