#!/usr/bin/env python3
"""Leak lab: real Barrier + Lifestream images, a real OpenVPN server and a fake internet
that logs where every connection comes from. Anything reaching the fake internet from
anywhere but the VPN server is a leak.

  python3 lab.py up [barrier-image] [lifestream-image]
  python3 lab.py down
  python3 lab.py <scenario>            see SCENARIOS
"""
import base64, hashlib, json, os, shlex, subprocess, sys, time, urllib.request

LAB = os.path.dirname(os.path.abspath(__file__))
RUN = os.path.join(LAB, "run")
EV = os.path.join(RUN, "log", "events.jsonl")
BARRIER_IP, VPN_IP, TARGET_IP, ISP_DNS, HOST_ON_INET = "192.168.77.10", "198.51.100.20", "198.51.100.50", "192.168.77.53", "198.51.100.1"
PW = "lab"
LS_UID = "1026:100"
IMAGES = {"barrier": "barrier-package:1.1.7", "lifestream": "lifestream-package:1.3.25"}
IMG_FILE = os.path.join(RUN, "images.json")


def sh(cmd, check=True, quiet=False):
    r = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if check and r.returncode:
        raise RuntimeError("%s\n%s%s" % (cmd, r.stdout, r.stderr))
    return r.stdout.strip()


def images():
    if os.path.exists(IMG_FILE):
        return json.load(open(IMG_FILE))
    return IMAGES


# ------------------------------------------------------------------ Barrier API
def bapi(path, method="GET", body=None, timeout=15):
    try:
        return _bapi(path, method, body, timeout)
    except (OSError, ValueError) as e:
        return {"_error": repr(e)[:120]}


def _bapi(path, method="GET", body=None, timeout=15):
    req = urllib.request.Request("http://%s:8085%s" % (BARRIER_IP, path), method=method,
                                 data=json.dumps(body).encode() if body is not None else None)
    req.add_header("Authorization", "Basic " + base64.b64encode(b"x:" + PW.encode()).decode())
    req.add_header("Content-Type", "application/json")
    req.add_header("X-Requested-With", "barrier")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        return {"_status": e.code, "_body": e.read().decode(errors="replace")[:300]}


def barrier_state():
    try:
        return bapi("/api/status", timeout=3).get("state", "unreachable")
    except Exception:
        return "unreachable"


def wait_barrier(states, timeout=60):
    end = time.time() + timeout
    while time.time() < end:
        s = barrier_state()
        if s in states:
            return s
        time.sleep(1)
    return barrier_state()


# ------------------------------------------------------------------ Lifestream RPC
_SID = [""]
LS_AUTH = "Basic " + base64.b64encode(b"lab:labpass").decode()


def ls_setup():
    req = urllib.request.Request("http://%s:9091/lifestream/api/setup" % BARRIER_IP, method="POST",
                                 data=json.dumps({"user": "lab", "pass": "labpass"}).encode(),
                                 headers={"X-Lifestream": "1", "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        return {"_status": e.code}


def rpc(method, args=None, timeout=10):
    for _ in range(3):
        req = urllib.request.Request("http://%s:9091/transmission/rpc" % BARRIER_IP, method="POST",
                                     data=json.dumps({"method": method, "arguments": args or {}}).encode())
        req.add_header("X-Transmission-Session-Id", _SID[0])
        req.add_header("Authorization", LS_AUTH)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return json.loads(r.read())
        except urllib.error.HTTPError as e:
            if e.code == 409:
                _SID[0] = e.headers.get("X-Transmission-Session-Id", "")
                continue
            raise
    raise RuntimeError("rpc failed")


def ls_state():
    req = urllib.request.Request("http://%s:9091/lifestream/api/state" % BARRIER_IP, headers={"X-Lifestream": "1", "Authorization": LS_AUTH})
    with urllib.request.urlopen(req, timeout=5) as r:
        return json.loads(r.read())


def ls_settings(patch=None):
    url = "http://%s:9091/lifestream/api/settings" % BARRIER_IP
    if patch is None:
        req = urllib.request.Request(url, headers={"X-Lifestream": "1", "Authorization": LS_AUTH})
    else:
        cur = ls_settings()
        cur.update(patch)
        req = urllib.request.Request(url, method="PUT", data=json.dumps(cur).encode(),
                                     headers={"X-Lifestream": "1", "Content-Type": "application/json", "Authorization": LS_AUTH})
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        return {"_status": e.code, "_body": e.read().decode(errors="replace")[:300]}


def wait_lifestream(timeout=60):
    end = time.time() + timeout
    while time.time() < end:
        try:
            return ls_state()
        except Exception:
            time.sleep(1)
    return None


def bencode(x):
    if isinstance(x, int):
        return b"i%de" % x
    if isinstance(x, bytes):
        return b"%d:%s" % (len(x), x)
    if isinstance(x, str):
        return bencode(x.encode())
    if isinstance(x, list):
        return b"l" + b"".join(bencode(i) for i in x) + b"e"
    return b"d" + b"".join(bencode(k) + bencode(v) for k, v in sorted(x.items())) + b"e"


def add_test_torrent(tag="a"):
    """A torrent nobody can serve: its tracker and peer are the logging fake internet."""
    data = hashlib.sha256(tag.encode()).digest() * (256 * 1024 // 32)
    piece = 256 * 1024
    pieces = b"".join(hashlib.sha1(data[i:i + piece]).digest() for i in range(0, len(data), piece))
    meta = {"announce": "http://tracker.lab:6969/announce",
            "info": {"name": "leaklab-%s.bin" % tag, "length": len(data), "piece length": piece, "pieces": pieces}}
    return rpc("torrent-add", {"metainfo": base64.b64encode(bencode(meta)).decode(), "paused": False})


# ------------------------------------------------------------------ events
def mark():
    return os.path.getsize(EV) if os.path.exists(EV) else 0


def events_since(pos):
    out = []
    if os.path.exists(EV):
        with open(EV) as f:
            f.seek(pos)
            for line in f:
                try:
                    out.append(json.loads(line))
                except ValueError:
                    pass
    return out


def leaks(evs):
    """Anything at the fake internet that didn't come out of the VPN server, and any lookup
    of a torrent name at the ISP's DNS."""
    bad = [e for e in evs if e["kind"] in ("tracker", "peer", "web", "vpnport") and e["src"] != VPN_IP]
    dns = [e for e in evs if e["kind"] == "dns-isp" and e.get("q", "").endswith((".lab", "bittorrent.com", "utorrent.com", "transmissionbt.com", "libtorrent.org"))]
    return bad, dns


def through_vpn(evs):
    return [e for e in evs if e["kind"] in ("tracker", "peer") and e["src"] == VPN_IP]


# ------------------------------------------------------------------ probes from inside Barrier's network
PROBE = r'''
import socket, sys, time
uid_note = sys.argv[1]; dur = float(sys.argv[2]); ok = 0; tries = 0
end = time.time() + dur
while time.time() < end:
    for proto, port in (("tcp", 6881), ("tcp", 80), ("tcp", 443), ("udp", 6881), ("udp", 1194), ("udp", 443)):
        tries += 1
        try:
            if proto == "tcp":
                s = socket.create_connection(("198.51.100.50", port), timeout=0.3); s.close(); ok += 1
            else:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.sendto(b"probe-" + uid_note.encode(), ("198.51.100.50", port)); s.close()
        except OSError:
            pass
    time.sleep(0.02)
print(ok, tries)
'''


def probe(uid, seconds):
    """Try to reach the fake internet directly from inside Barrier's network as `uid`
    (1026 = Lifestream's user on the NAS, 0 = root). Returns (tcp successes, attempts)."""
    out = sh("docker exec -u %s barrier python -c %s %s %s" % (uid, shlex.quote(PROBE), uid, seconds), check=False)
    try:
        a, b = out.split()[-2:]
        return int(a), int(b)
    except ValueError:
        return None, out


# ------------------------------------------------------------------ lab setup
def run_barrier(img):
    os.makedirs(os.path.join(RUN, "bconf"), exist_ok=True)
    sh("docker run -d --name barrier --network home --ip %s --dns %s --cap-add NET_ADMIN --device /dev/net/tun "
       "--user 0:0 -e UI_PASSWORD=%s -e REJOIN_EVERY=5 -e REJOIN_FIRST_DELAY=2 -e NO_INTERNET_RECONNECT=60 "
       "-v %s/bconf:/config -v /var/run/docker.sock:/var/run/docker.sock --restart unless-stopped %s"
       % (BARRIER_IP, ISP_DNS, PW, RUN, img))


def run_lifestream(img):
    os.makedirs(os.path.join(RUN, "lconf"), exist_ok=True)
    os.chmod(os.path.join(RUN, "lconf"), 0o777)
    sh("docker run -d --name lifestream --network container:barrier --user %s "
       "-e LIFESTREAM_ADAPTER=tun0 -e LIFESTREAM_DOWNLOAD_DIR=/config/dl -v %s/lconf:/config "
       "--restart unless-stopped %s" % (LS_UID, RUN, img))


def make_pki():
    """Throwaway certificates for the test VPN server (made once, never committed)."""
    d = os.path.join(LAB, "pki")
    if os.path.exists(os.path.join(d, "server.crt")):
        return
    os.makedirs(d, exist_ok=True)
    sh("cd %s && openssl req -x509 -newkey rsa:2048 -nodes -keyout ca.key -out ca.crt -days 30 -subj /CN=lab-ca 2>/dev/null"
       " && openssl req -newkey rsa:2048 -nodes -keyout server.key -out server.csr -subj /CN=lab-vpn 2>/dev/null"
       " && printf 'basicConstraints=CA:FALSE\\nkeyUsage=digitalSignature,keyEncipherment\\nextendedKeyUsage=serverAuth\\n' > ext.cnf"
       " && openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt -days 30 -extfile ext.cnf 2>/dev/null"
       " && printf '#!/bin/sh\\nexit 0\\n' > ok.sh && chmod 755 ok.sh && chmod 644 *.key" % d)


def up(bimg=None, limg=None):
    down()
    make_pki()
    imgs = dict(IMAGES)
    if bimg:
        imgs["barrier"] = bimg
    if limg:
        imgs["lifestream"] = limg
    os.makedirs(os.path.join(RUN, "log"), exist_ok=True)
    json.dump(imgs, open(IMG_FILE, "w"))
    open(EV, "w").close()
    os.chmod(os.path.join(RUN, "log"), 0o777)
    os.chmod(EV, 0o666)
    sh("docker network create --subnet 192.168.77.0/24 home >/dev/null")
    sh("docker network create --subnet 198.51.100.0/24 inet >/dev/null")
    # The host plays the home router: forward between the networks (Docker NATs home -> inet).
    if subprocess.run("iptables -C DOCKER-USER -j ACCEPT", shell=True, capture_output=True).returncode:
        sh("iptables -I DOCKER-USER -j ACCEPT")
    # Newer Docker drops traffic into a container from another bridge; let home reach the internet.
    if subprocess.run("iptables -t raw -C PREROUTING -s 192.168.77.0/24 -d 198.51.100.0/24 -j ACCEPT", shell=True, capture_output=True).returncode:
        sh("iptables -t raw -I PREROUTING -s 192.168.77.0/24 -d 198.51.100.0/24 -j ACCEPT")
    b = imgs["barrier"]
    sh("docker run -d --name target --network inet --ip %s -v %s:/lab -v %s/log:/log --entrypoint python %s /lab/netsvc.py target /log/events.jsonl" % (TARGET_IP, LAB, RUN, b))
    sh("docker run -d --name ispdns --network home --ip %s -v %s:/lab -v %s/log:/log --entrypoint python %s /lab/netsvc.py dns /log/events.jsonl isp %s" % (ISP_DNS, LAB, RUN, b, TARGET_IP))
    sh("docker run -d --name vpnserver --network inet --ip %s --cap-add NET_ADMIN --device /dev/net/tun --sysctl net.ipv4.ip_forward=1 "
       "-v %s:/lab -v %s/pki:/pki -v %s/log:/log --entrypoint sh %s /lab/vpnserver.sh" % (VPN_IP, LAB, LAB, RUN, b))
    run_barrier(b)
    for _ in range(60):
        if barrier_state() != "unreachable":
            break
        time.sleep(1)
    ca = open(os.path.join(LAB, "pki", "ca.crt")).read()
    ovpn = "client\ndev tun\nproto udp\nremote %s 1194\nnobind\nremote-cert-tls server\nverb 3\n<ca>\n%s</ca>\n" % (VPN_IP, ca)
    os.makedirs(os.path.join(RUN, "bconf", "configs"), exist_ok=True)
    open(os.path.join(RUN, "bconf", "configs", "my_expressvpn_lab_-_test_udp.ovpn"), "w").write(ovpn)
    print("credentials:", bapi("/api/credentials", "POST", {"username": "lab", "password": "lab"}))
    print("settings:", bapi("/api/settings", "POST", {"auto_update": False, "kill_switch": True, "auto_connect": True}))
    print("connect:", bapi("/api/connect", "POST", {"key": "lab_-_test"}))
    print("barrier:", wait_barrier({"connected"}, 60))
    run_lifestream(images()["lifestream"])
    wait_lifestream(60)
    print("lifestream setup:", ls_setup())
    time.sleep(2)
    st = wait_lifestream(30)
    print("torrent:", add_test_torrent("a").get("result"))
    print("lifestream:", st and {k: st.get(k) for k in ("version", "adapter", "adapterIp", "killHold", "killReason")})


def down():
    for c in ("lifestream", "barrier", "vpnserver", "target", "ispdns"):
        sh("docker rm -f %s" % c, check=False)
    for n in ("home", "inet"):
        sh("docker network rm %s" % n, check=False)
    sh("rm -rf %s/bconf %s/lconf" % (RUN, RUN), check=False)


if __name__ == "__main__":
    cmd = sys.argv[1]
    if cmd == "up":
        up(*sys.argv[2:4])
    elif cmd == "down":
        down()
    else:
        import scenarios
        scenarios.main(sys.argv[1:])
