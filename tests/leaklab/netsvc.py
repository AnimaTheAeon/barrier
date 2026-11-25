"""Stand-in internet services for the leak lab. Every contact is logged with its source IP.

  python netsvc.py target <logfile>   tracker (6969/tcp), peer (6881 tcp+udp), web (80/tcp)
  python netsvc.py dns <logfile> <name> <answer-ip> [bind-ip]   DNS that answers every A query
"""
import json
import socket
import socketserver
import struct
import sys
import threading
import time
import http.server

LOG = None
LOCK = threading.Lock()
MY_IP = "198.51.100.50"


def log(kind, src, **kw):
    with LOCK, open(LOG, "a") as f:
        f.write(json.dumps(dict(t=round(time.time(), 3), kind=kind, src=src, **kw)) + "\n")


def bencode(x):
    if isinstance(x, int):
        return b"i%de" % x
    if isinstance(x, bytes):
        return b"%d:%s" % (len(x), x)
    if isinstance(x, str):
        return bencode(x.encode())
    if isinstance(x, list):
        return b"l" + b"".join(bencode(i) for i in x) + b"e"
    if isinstance(x, dict):
        return b"d" + b"".join(bencode(k) + bencode(v) for k, v in sorted(x.items())) + b"e"
    raise TypeError(x)


class Tracker(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        log("tracker", self.client_address[0], path=self.path[:120])
        peers = socket.inet_aton(MY_IP) + struct.pack(">H", 6881)
        body = bencode({"interval": 30, "peers": peers})
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


class Web(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        log("web", self.client_address[0], path=self.path[:120])
        body = (self.client_address[0] + "\n").encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


def tcp_logger(port, kind):
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", port))
    s.listen(64)
    while True:
        c, a = s.accept()
        log(kind, a[0], proto="tcp", port=port)
        c.close()


def udp_logger(port, kind):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("0.0.0.0", port))
    while True:
        _, a = s.recvfrom(4096)
        log(kind, a[0], proto="udp", port=port)


def dns(name, answer, bind="0.0.0.0"):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    while True:
        try:
            s.bind((bind, 53))
            break
        except OSError:
            time.sleep(1)  # the tunnel address may not exist yet
    while True:
        data, a = s.recvfrom(1500)
        try:
            qid, flags, qd = struct.unpack(">HHH", data[:6])
            i, labels = 12, []
            while data[i]:
                labels.append(data[i + 1:i + 1 + data[i]].decode(errors="replace"))
                i += data[i] + 1
            qname = ".".join(labels)
            qtype = struct.unpack(">H", data[i + 1:i + 3])[0]
            question = data[12:i + 5]
            log("dns-" + name, a[0], q=qname, qtype=qtype)
            if qtype == 1:
                ans = b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 30, 4) + socket.inet_aton(answer)
                resp = struct.pack(">HHHHHH", qid, 0x8180, 1, 1, 0, 0) + question + ans
            else:
                resp = struct.pack(">HHHHHH", qid, 0x8180, 1, 0, 0, 0) + question
            s.sendto(resp, a)
        except Exception:
            pass


def serve(handler, port):
    srv = socketserver.ThreadingTCPServer(("0.0.0.0", port), handler)
    srv.daemon_threads = True
    srv.serve_forever()


if __name__ == "__main__":
    mode, LOG = sys.argv[1], sys.argv[2]
    if mode == "target":
        socketserver.ThreadingTCPServer.allow_reuse_address = True
        threading.Thread(target=serve, args=(Tracker, 6969), daemon=True).start()
        threading.Thread(target=serve, args=(Web, 80), daemon=True).start()
        threading.Thread(target=tcp_logger, args=(6881, "peer"), daemon=True).start()
        threading.Thread(target=udp_logger, args=(6881, "peer"), daemon=True).start()
        for p in (1194, 443):  # the VPN handshake ports, to catch traffic that hides behind them
            threading.Thread(target=udp_logger, args=(p, "vpnport"), daemon=True).start()
        threading.Thread(target=tcp_logger, args=(443, "vpnport"), daemon=True).start()
        log("start", MY_IP)
        while True:
            time.sleep(3600)
    elif mode == "dns":
        dns(sys.argv[3], sys.argv[4], sys.argv[5] if len(sys.argv) > 5 else "0.0.0.0")
