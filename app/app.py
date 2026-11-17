#!/usr/bin/env python3
"""Barrier - a small web GUI that drives OpenVPN with ExpressVPN manual-config files.

Runs inside a Docker container on a Synology NAS. Everything the user needs
(credentials, location files, connect/disconnect, kill switch) is in the browser.
"""
import hashlib
import hmac
import io
import ipaddress
import json
import os
import random
import re
import shutil
import signal
import socket
import subprocess
import sys
import tarfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from collections import deque

from flask import Flask, Response, jsonify, request, send_from_directory

# --------------------------------------------------------------------------
# Settings from the environment
# --------------------------------------------------------------------------
CONFIG_DIR = os.environ.get("CONFIG_DIR", "/config")
OPENVPN_BIN = os.environ.get("OPENVPN_BIN", "openvpn")
SCRIPT_DIR = os.environ.get("SCRIPT_DIR", os.path.join(os.path.dirname(os.path.abspath(__file__)), "scripts"))
STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")
TUN_DEV = "tun0"
DRY_FIREWALL = os.environ.get("DRY_RUN_FIREWALL") == "1"
ENV_PASSWORD = os.environ.get("UI_PASSWORD", "")
IP_CHECK_URL = os.environ.get("IP_CHECK_URL", "https://api.ipify.org")
PORT = int(os.environ.get("PORT", "8085"))
DNS_FALLBACK = os.environ.get("DNS_FALLBACK", "1.1.1.1")
RUNTIME_CFG = os.environ.get("RUNTIME_CFG", "/tmp/barrier-runtime.ovpn")
DEFAULT_LAN = os.environ.get("LAN_SUBNETS", "192.168.0.0/16,172.16.0.0/12,10.0.0.0/8")

APP_DIR = os.path.dirname(os.path.abspath(__file__))
try:
    with open(os.path.join(APP_DIR, "VERSION")) as _f:
        VERSION = _f.read().strip() or "0"
except OSError:
    VERSION = "0"
# Updates: the package's start script sets BARRIER_UPDATE_DIR and swaps in what
# lands in <dir>/next when the app exits with UPDATE_EXIT.
UPDATE_DIR = os.environ.get("BARRIER_UPDATE_DIR", "")
RELEASE_URL = os.environ.get("BARRIER_RELEASE_URL", "https://api.github.com/repos/AnimaTheAeon/Barrier/releases/latest")
UPDATE_EXIT = 75

CONFIGS_DIR = os.path.join(CONFIG_DIR, "configs")
SETTINGS_FILE = os.path.join(CONFIG_DIR, "settings.json")
AUTH_FILE = os.path.join(CONFIG_DIR, "auth.txt")
# The page password: set in Settings (kept here), or UI_PASSWORD from the environment.
PASSWORD_FILE = os.path.join(CONFIG_DIR, "page-password")


def page_password():
    if ENV_PASSWORD:
        return ENV_PASSWORD
    try:
        with open(PASSWORD_FILE) as f:
            return f.read().strip()
    except OSError:
        return ""
CHAIN = "NASVPN_KS"

MAX_CONFIG_BYTES = 200 * 1024
MAX_UPLOAD_BYTES = 40 * 1024 * 1024

os.makedirs(CONFIGS_DIR, exist_ok=True)

# --------------------------------------------------------------------------
# Settings persistence
# --------------------------------------------------------------------------
_settings_lock = threading.Lock()


def _default_settings():
    return {
        "kill_switch": True,
        "auto_connect": False,
        "auto_update": True,
        "last_config": "",
        "protocol": "udp",
        "lan_subnets": [s.strip() for s in DEFAULT_LAN.split(",") if s.strip()],
    }


def load_settings():
    s = _default_settings()
    try:
        with open(SETTINGS_FILE) as f:
            s.update(json.load(f))
    except (OSError, ValueError):
        pass
    return s


def save_settings(s):
    with _settings_lock:
        tmp = SETTINGS_FILE + ".tmp"
        with open(tmp, "w") as f:
            json.dump(s, f, indent=2)
        os.replace(tmp, SETTINGS_FILE)


def clean_subnets(items):
    out = []
    for item in items:
        item = str(item).strip()
        if not item:
            continue
        net = ipaddress.ip_network(item, strict=False)  # raises ValueError if bad
        if net.version != 4:
            raise ValueError("only IPv4 ranges are supported")
        out.append(str(net))
    return out


# --------------------------------------------------------------------------
# .ovpn parsing / sanitising
# --------------------------------------------------------------------------
# Directives that could run programs, write files or take over OpenVPN. A config
# file is untrusted input, so these are dropped from the copy we actually run.
BLOCKED = {
    "up", "down", "route-up", "route-pre-down", "down-pre", "up-restart", "up-delay",
    "tls-verify", "ipchange", "client-connect", "client-disconnect", "learn-address",
    "auth-user-pass-verify", "plugin", "script-security", "management",
    "management-client", "management-query-passwords", "management-hold",
    "management-log-cache", "management-client-user", "management-client-group",
    "log", "log-append", "writepid", "daemon", "config", "askpass", "auth-user-pass",
    "route-method", "dev", "dev-type", "dev-node", "status", "status-version", "cd",
    "chroot", "user", "group", "syslog", "setenv", "setenv-safe", "tmp-dir",
    "echo", "tls-export-cert", "remap-usr1", "ifconfig-noexec",
    "route-noexec", "route-nopull", "pull-filter",
}
ACRONYMS = {"usa", "uk", "uae", "drc"}
_cache = {}


def _proto_from(value):
    value = (value or "").lower()
    return "tcp" if value.startswith("tcp") else "udp"


def sanitize_ovpn(text):
    """Return (clean_text, remotes[(host, port, proto)], proto)."""
    out, remotes = [], []
    proto = None
    block = None
    for raw in text.replace("\r\n", "\n").replace("\r", "\n").split("\n"):
        line = raw.strip()
        if block:
            out.append(raw)
            if line == "</%s>" % block:
                block = None
            continue
        m = re.match(r"^<([A-Za-z0-9_-]+)>$", line)
        if m:
            block = m.group(1)
            out.append(raw)
            continue
        if not line or line[0] in "#;":
            continue
        parts = line.split()
        key = parts[0].lower()
        if key in BLOCKED:
            continue
        if key == "proto" and len(parts) > 1:
            proto = _proto_from(parts[1])
        if key == "remote" and len(parts) > 1:
            host = parts[1]
            port = parts[2] if len(parts) > 2 and parts[2].isdigit() else "1194"
            rp = _proto_from(parts[3]) if len(parts) > 3 else None
            remotes.append((host, int(port), rp))
        out.append(line)
    proto = proto or "udp"
    remotes = [(h, p, rp or proto) for h, p, rp in remotes]
    return "\n".join(out) + "\n", remotes, proto


def pretty_location(filename):
    base = re.sub(r"\.ovpn$", "", filename, flags=re.I)
    base = re.sub(r"^my[_-]?expressvpn[_-]", "", base, flags=re.I)
    m = re.search(r"[_-](udp|tcp)$", base, re.I)
    proto = m.group(1).lower() if m else None
    if m:
        base = base[: m.start()]
    key = base.lower()
    text = re.sub(r"_+", " ", base).strip()
    text = re.sub(r"\s*-\s*", " - ", text)
    words = []
    for w in text.split(" "):
        if w.lower() in ACRONYMS:
            words.append(w.upper())
        elif w.islower():
            words.append(w.capitalize())
        else:
            words.append(w)
    name = " ".join(words)
    country = name.split(" - ")[0] if " - " in name else name
    return key, name, country, proto


def safe_filename(name):
    name = os.path.basename(name.replace("\\", "/"))
    name = re.sub(r"[^A-Za-z0-9._() -]", "_", name).strip(". ")
    if not name.lower().endswith(".ovpn"):
        return None
    return name


def list_locations():
    """Group config files into locations with their UDP/TCP variants."""
    groups = {}
    try:
        files = sorted(f for f in os.listdir(CONFIGS_DIR) if f.lower().endswith(".ovpn"))
    except OSError:
        files = []
    for fn in files:
        key, name, country, proto = pretty_location(fn)
        if proto is None:
            path = os.path.join(CONFIGS_DIR, fn)
            try:
                mtime = os.path.getmtime(path)
                cached = _cache.get(fn)
                if cached and cached[0] == mtime:
                    proto = cached[1]
                else:
                    with open(path, errors="replace") as f:
                        proto = sanitize_ovpn(f.read())[2]
                    _cache[fn] = (mtime, proto)
            except OSError:
                proto = "udp"
        g = groups.setdefault(key, {"key": key, "name": name, "country": country, "files": {}})
        g["files"][proto] = fn
    locs = sorted(groups.values(), key=lambda g: (g["country"].lower(), g["name"].lower()))
    for g in locs:
        g["protocols"] = sorted(g["files"])
    return locs


def resolve_file(key, proto_pref):
    for loc in list_locations():
        if loc["key"] == key:
            files = loc["files"]
            if proto_pref in files:
                return files[proto_pref], proto_pref, loc["name"]
            p = sorted(files)[0]
            return files[p], p, loc["name"]
    return None, None, None


def location_name_for_file(fn):
    return pretty_location(fn)[1] if fn else ""


# --------------------------------------------------------------------------
# Firewall / kill switch
# --------------------------------------------------------------------------
class Firewall:
    def __init__(self):
        self.bin4 = None
        self.bin6 = None
        self.available = False
        self.rules_log = []  # used in dry-run mode so tests can inspect
        self._detect()

    def _run(self, binary, *args):
        if DRY_FIREWALL:
            self.rules_log.append(" ".join([binary, *args]))
            return 0
        try:
            return subprocess.run([binary, "-w", *args], capture_output=True, text=True, timeout=15).returncode
        except (OSError, subprocess.TimeoutExpired):
            return 127

    def _detect(self):
        if DRY_FIREWALL:
            self.bin4, self.bin6, self.available = "iptables", "ip6tables", True
            return
        # Synology's kernel is old and usually has no nf_tables, so try the legacy tools first.
        for b4, b6 in (("iptables-legacy", "ip6tables-legacy"), ("iptables", "ip6tables")):
            if shutil.which(b4) and self._run(b4, "-L", "-n") == 0:
                self.bin4, self.bin6, self.available = b4, b6, True
                return

    def apply(self, lan_subnets, remote_ports):
        """Block everything except loopback, the tunnel, the LAN and the VPN handshake ports."""
        if not self.available:
            return False
        b = self.bin4
        self._run(b, "-N", CHAIN)
        self._run(b, "-F", CHAIN)
        self._run(b, "-A", CHAIN, "-o", "lo", "-j", "ACCEPT")
        self._run(b, "-A", CHAIN, "-o", "tun+", "-j", "ACCEPT")
        for net in lan_subnets:
            self._run(b, "-A", CHAIN, "-d", net, "-j", "ACCEPT")
        for proto, port in sorted(remote_ports):
            self._run(b, "-A", CHAIN, "-p", proto, "--dport", str(port), "-j", "ACCEPT")
        self._run(b, "-A", CHAIN, "-j", "DROP")
        if self._run(b, "-C", "OUTPUT", "-j", CHAIN) != 0:
            self._run(b, "-I", "OUTPUT", "1", "-j", CHAIN)
        # IPv6: nothing but loopback and the tunnel. Not every kernel has ip6tables; that's fine.
        b6 = self.bin6
        if b6 and (DRY_FIREWALL or shutil.which(b6)):
            self._run(b6, "-N", CHAIN)
            self._run(b6, "-F", CHAIN)
            self._run(b6, "-A", CHAIN, "-o", "lo", "-j", "ACCEPT")
            self._run(b6, "-A", CHAIN, "-o", "tun+", "-j", "ACCEPT")
            self._run(b6, "-A", CHAIN, "-j", "DROP")
            if self._run(b6, "-C", "OUTPUT", "-j", CHAIN) != 0:
                self._run(b6, "-I", "OUTPUT", "1", "-j", CHAIN)
        return True

    def clear(self):
        if not self.available:
            return
        for b in (self.bin4, self.bin6):
            if not b:
                continue
            while self._run(b, "-D", "OUTPUT", "-j", CHAIN) == 0 and not DRY_FIREWALL:
                pass
            self._run(b, "-F", CHAIN)
            self._run(b, "-X", CHAIN)


FW = Firewall()

# --------------------------------------------------------------------------
# VPN controller
# --------------------------------------------------------------------------
LOG_RE_TIMESTAMP = re.compile(r"^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d ")


class Vpn:
    def __init__(self):
        self.lock = threading.RLock()
        self.proc = None
        self.desired = None       # config filename we want to be connected to
        self.current = None       # config filename currently running
        self.state = "disconnected"
        self.message = ""
        self.connected_at = None
        self.retry = 0
        self.next_try = 0.0
        self.log = deque(maxlen=500)
        self.ip = None
        self.ip_checked = 0.0
        self.ip_busy = False

    # ---- logging -----------------------------------------------------
    def _log(self, text):
        self.log.append("%s %s" % (time.strftime("%H:%M:%S"), text.rstrip()))

    # ---- build the config we really run -------------------------------
    def _prepare(self, filename):
        path = os.path.join(CONFIGS_DIR, filename)
        with open(path, errors="replace") as f:
            clean, remotes, proto = sanitize_ovpn(f.read())
        settings = load_settings()
        extra = [
            "",
            "# ---- added by Barrier ----",
            "dev %s" % TUN_DEV,
            "auth-user-pass %s" % AUTH_FILE,
            "auth-nocache",
            "script-security 2",
            "route-up %s/route-up.sh" % SCRIPT_DIR,
            "down %s/down.sh" % SCRIPT_DIR,
            "down-pre",
            "redirect-gateway def1",
            "resolv-retry 15",
            "data-ciphers AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305:AES-256-CBC",
            "data-ciphers-fallback AES-256-CBC",
            'pull-filter ignore "ifconfig-ipv6"',
            'pull-filter ignore "route-ipv6"',
            'pull-filter ignore "redirect-gateway ipv6"',
        ]
        for net in settings["lan_subnets"]:
            n = ipaddress.ip_network(net, strict=False)
            if n.version == 4:
                extra.append("route %s %s net_gateway" % (n.network_address, n.netmask))
        with open(RUNTIME_CFG, "w") as f:
            f.write(clean + "\n".join(extra) + "\n")
        os.chmod(RUNTIME_CFG, 0o600)
        ports = {(rp, port) for _, port, rp in remotes}
        return ports

    # ---- start / stop ---------------------------------------------------
    def _launch(self):
        filename = self.desired
        if not filename:
            return
        settings = load_settings()
        try:
            ports = self._prepare(filename)
        except OSError as e:
            self.state, self.message, self.desired = "error", "Could not read location file: %s" % e, None
            return
        if settings["kill_switch"]:
            FW.apply(settings["lan_subnets"], ports)
        self._log("Starting OpenVPN for %s" % location_name_for_file(filename))
        try:
            proc = subprocess.Popen(
                [OPENVPN_BIN, "--config", RUNTIME_CFG],
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1,
                env=dict(os.environ, NASVPN_DNS_FALLBACK=DNS_FALLBACK),
            )
        except OSError as e:
            self.state, self.message, self.desired = "error", "Could not start OpenVPN: %s" % e, None
            self._log(self.message)
            return
        self.proc, self.current = proc, filename
        self.state = "reconnecting" if self.retry else "connecting"
        self.message = ""
        self.connected_at = None
        threading.Thread(target=self._reader, args=(proc,), daemon=True).start()

    def _reader(self, proc):
        for line in proc.stdout:
            line = line.rstrip()
            if not line:
                continue
            with self.lock:
                self._log(LOG_RE_TIMESTAMP.sub("", line))
                if self.proc is not proc:
                    continue
                if "Initialization Sequence Completed" in line:
                    self.state, self.message = "connected", ""
                    self.connected_at = time.time()
                    self.retry = 0
                    self.ip, self.ip_checked = None, time.time() - 117  # look up the new IP in ~3s
                elif "AUTH_FAILED" in line:
                    self.state = "auth_failed"
                    self.message = "ExpressVPN rejected the username/password. Re-enter them from the Manual Config page."
                    self.desired = None
                elif "Options error" in line:
                    self.state, self.message, self.desired = "error", "This location file has a problem: " + line.split("Options error:")[-1].strip(), None
                elif re.search(r"SIGUSR1|SIGHUP", line) and self.state == "connected":
                    self.state, self.connected_at = "reconnecting", None
                elif "TLS Error: TLS key negotiation failed" in line and self.state != "connected":
                    self.message = "Can't reach the VPN server yet (retrying)."
        proc.wait()
        with self.lock:
            if self.proc is not proc:
                return
            self._log("OpenVPN exited (code %s)" % proc.returncode)
            self.proc = None
            self.connected_at = None
            if self.desired:
                self.retry += 1
                self.next_try = time.time() + min(5 * 2 ** (self.retry - 1), 60)
                self.state = "reconnecting"
            elif self.state not in ("auth_failed", "error"):
                self.state = "disconnected"

    def connect(self, filename):
        with self.lock:
            self._stop_locked()
            self.desired = filename
            self.retry = 0
            self.message = ""
            s = load_settings()
            s["last_config"] = filename
            save_settings(s)
            self._launch()

    def _stop_locked(self):
        proc, self.proc = self.proc, None
        self.desired = None
        if proc and proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=8)
            except subprocess.TimeoutExpired:
                proc.kill()
        self.current, self.connected_at = None, None
        self.state, self.message = "disconnected", ""
        self.ip, self.ip_checked = None, 0.0

    def disconnect(self):
        with self.lock:
            self._stop_locked()
            self._log("Disconnected")
            s = load_settings()
            if s["kill_switch"]:
                FW.apply(s["lan_subnets"], set())
            else:
                FW.clear()

    def watchdog(self):
        while True:
            time.sleep(1)
            with self.lock:
                if self.desired and self.proc is None and time.time() >= self.next_try:
                    self._launch()
            # public IP refresh
            if (self.state == "connected" or self.state == "disconnected") and not self.ip_busy \
                    and time.time() - self.ip_checked > 120:
                self.refresh_ip()

    def refresh_ip(self):
        if self.ip_busy:
            return
        self.ip_busy = True
        self.ip_checked = time.time()

        def work():
            try:
                with urllib.request.urlopen(IP_CHECK_URL, timeout=6) as r:
                    ip = r.read(64).decode().strip()
                self.ip = ip if re.match(r"^[0-9a-fA-F:.]+$", ip) else None
            except Exception:
                self.ip = None
                self.ip_checked = time.time() - 100  # try again in ~20s
            finally:
                self.ip_busy = False

        threading.Thread(target=work, daemon=True).start()

    # ---- reporting -------------------------------------------------------
    def counters(self):
        base = "/sys/class/net/%s/statistics/" % TUN_DEV
        try:
            with open(base + "rx_bytes") as f:
                rx = int(f.read())
            with open(base + "tx_bytes") as f:
                tx = int(f.read())
            return rx, tx
        except (OSError, ValueError):
            return 0, 0

    def status(self):
        s = load_settings()
        with self.lock:
            rx, tx = self.counters() if self.state == "connected" else (0, 0)
            return {
                "state": self.state,
                "message": self.message,
                "location": location_name_for_file(self.current) if self.current else "",
                "last_location": location_name_for_file(s["last_config"]) if s["last_config"] else "",
                "uptime": int(time.time() - self.connected_at) if self.connected_at else 0,
                "rx": rx, "tx": tx,
                "ip": self.ip,
                "kill_switch": s["kill_switch"],
                "firewall_ok": FW.available,
                "auto_connect": s["auto_connect"],
                "has_credentials": os.path.exists(AUTH_FILE),
                "location_count": len(list_locations()),
                "ui_password": bool(page_password()),
                "password_from_env": bool(ENV_PASSWORD),
                "version": VERSION,
            }


VPN = Vpn()

# --------------------------------------------------------------------------
# Flask app
# --------------------------------------------------------------------------
app = Flask(__name__, static_folder=None)
app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_BYTES


@app.before_request
def guard():
    if request.path == "/api/health":
        return None
    pw = page_password()
    if pw:
        auth = request.authorization
        if not auth or not hmac.compare_digest(auth.password or "", pw):
            return Response("Password required", 401, {"WWW-Authenticate": 'Basic realm="Barrier"'})
    if request.method in ("POST", "PUT", "DELETE") and request.headers.get("X-Requested-With") != "barrier":
        return jsonify(error="Missing header"), 403
    return None


@app.after_request
def headers(resp):
    resp.headers["Cache-Control"] = "no-store"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    return resp


def err(msg, code=400):
    return jsonify(error=msg), code


@app.route("/")
def index():
    return send_from_directory(STATIC_DIR, "index.html")


@app.route("/favicon.ico")
def favicon():
    return "", 204


@app.route("/api/health")
def health():
    return jsonify(ok=True)


@app.route("/api/status")
def api_status():
    return jsonify(VPN.status())


@app.route("/api/locations")
def api_locations():
    s = load_settings()
    return jsonify(locations=[{k: v for k, v in l.items() if k != "files"} for l in list_locations()],
                   protocol=s["protocol"], last=pretty_location(s["last_config"])[0] if s["last_config"] else "")


@app.route("/api/connect", methods=["POST"])
def api_connect():
    data = request.get_json(silent=True) or {}
    if not os.path.exists(AUTH_FILE):
        return err("Enter your ExpressVPN username and password first.")
    s = load_settings()
    proto = data.get("protocol") or s["protocol"]
    if data.get("random"):
        locs = list_locations()
        if not locs:
            return err("Upload some location files first.")
        key = random.choice(locs)["key"]
    elif data.get("last"):
        if not s["last_config"] or not os.path.exists(os.path.join(CONFIGS_DIR, s["last_config"])):
            return err("No previous location to reconnect to.")
        VPN.connect(s["last_config"])
        return jsonify(ok=True)
    else:
        key = data.get("key", "")
    fn, used, _ = resolve_file(key, proto)
    if not fn:
        return err("Unknown location.", 404)
    VPN.connect(fn)
    return jsonify(ok=True, protocol=used)


@app.route("/api/disconnect", methods=["POST"])
def api_disconnect():
    VPN.disconnect()
    return jsonify(ok=True)


@app.route("/api/settings", methods=["GET", "POST"])
def api_settings():
    s = load_settings()
    if request.method == "POST":
        d = request.get_json(silent=True) or {}
        for k in ("kill_switch", "auto_connect", "auto_update"):
            if k in d:
                s[k] = bool(d[k])
        if d.get("protocol") in ("udp", "tcp"):
            s["protocol"] = d["protocol"]
        if "lan_subnets" in d:
            raw = d["lan_subnets"]
            items = raw.split(",") if isinstance(raw, str) else list(raw)
            try:
                s["lan_subnets"] = clean_subnets(items)
            except ValueError as e:
                return err("That network range isn't valid: %s" % e)
        save_settings(s)
        # apply kill-switch change immediately
        with VPN.lock:
            if s["kill_switch"]:
                ports = set()
                if VPN.current:
                    try:
                        with open(os.path.join(CONFIGS_DIR, VPN.current), errors="replace") as f:
                            ports = {(rp, p) for _, p, rp in sanitize_ovpn(f.read())[1]}
                    except OSError:
                        pass
                FW.apply(s["lan_subnets"], ports)
            else:
                FW.clear()
    return jsonify(kill_switch=s["kill_switch"], auto_connect=s["auto_connect"], protocol=s["protocol"],
                   lan_subnets=s["lan_subnets"], auto_update=s["auto_update"])


@app.route("/api/password", methods=["POST"])
def api_password():
    """Set or remove the page password (the browser asks for it; any username works)."""
    if ENV_PASSWORD:
        return err("The password is set by UI_PASSWORD in the container's settings, so it can't be changed here.")
    pw = str((request.get_json(silent=True) or {}).get("password", "")).strip()
    if pw:
        if len(pw) < 6:
            return err("Use at least 6 characters.")
        fd = os.open(PASSWORD_FILE + ".tmp", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(pw)
        os.replace(PASSWORD_FILE + ".tmp", PASSWORD_FILE)
    else:
        try:
            os.remove(PASSWORD_FILE)
        except FileNotFoundError:
            pass
    return jsonify(ok=True, ui_password=bool(pw))


@app.route("/api/credentials", methods=["GET", "POST"])
def api_credentials():
    if request.method == "POST":
        d = request.get_json(silent=True) or {}
        user, pw = str(d.get("username", "")).strip(), str(d.get("password", "")).strip()
        if not user or not pw:
            return err("Both username and password are needed.")
        if "\n" in user or "\n" in pw:
            return err("Username and password must be on one line each.")
        fd = os.open(AUTH_FILE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(user + "\n" + pw + "\n")
        return jsonify(ok=True)
    user = ""
    try:
        with open(AUTH_FILE) as f:
            user = f.readline().strip()
    except OSError:
        pass
    return jsonify(has=bool(user), username=user)


@app.route("/api/upload", methods=["POST"])
def api_upload():
    saved, skipped = 0, []

    def store(name, data):
        nonlocal saved
        fn = safe_filename(name)
        if not fn:
            return
        if len(data) > MAX_CONFIG_BYTES:
            skipped.append(name)
            return
        text = data.decode("utf-8", errors="replace")
        if not re.search(r"^\s*remote\s+\S+", text, re.M):
            skipped.append(name)
            return
        with open(os.path.join(CONFIGS_DIR, fn), "w") as f:
            f.write(text)
        saved += 1

    for f in request.files.getlist("files"):
        name = f.filename or ""
        data = f.read()
        if name.lower().endswith(".zip"):
            try:
                with zipfile.ZipFile(io.BytesIO(data)) as z:
                    total = 0
                    for info in z.infolist():
                        if info.is_dir() or not info.filename.lower().endswith(".ovpn"):
                            continue
                        if info.file_size > MAX_CONFIG_BYTES:
                            skipped.append(info.filename)
                            continue
                        total += info.file_size
                        if total > MAX_UPLOAD_BYTES:
                            break
                        store(info.filename, z.read(info))
            except zipfile.BadZipFile:
                skipped.append(name)
        else:
            store(name, data)
    return jsonify(saved=saved, skipped=skipped, total=len(list_locations()))


@app.route("/api/configs/clear", methods=["POST"])
def api_clear():
    with VPN.lock:
        if VPN.desired or VPN.proc:
            return err("Disconnect first, then remove location files.")
    for fn in os.listdir(CONFIGS_DIR):
        if fn.lower().endswith(".ovpn"):
            os.remove(os.path.join(CONFIGS_DIR, fn))
    return jsonify(ok=True)


@app.route("/api/ip", methods=["POST"])
def api_ip():
    VPN.ip_checked = 0
    VPN.ip = None
    VPN.refresh_ip()
    return jsonify(ok=True)


@app.route("/api/selftest", methods=["GET", "POST"])
def api_selftest():
    if request.method == "POST":
        d = request.get_json(silent=True) or {}
        deep = bool(d.get("deep"))
        if deep:
            if VPN.state != "connected":
                return err("Connect to a location first. The drop test needs an active VPN.")
            if not load_settings()["kill_switch"] or not FW.available:
                return err("Turn the kill switch on first. That's the thing this test checks.")
        with _selftest_lock:
            if SELFTEST["running"]:
                return err("A test is already running.", 409)
            SELFTEST["running"] = True
        threading.Thread(target=_selftest_worker, args=(deep,), daemon=True).start()
        return jsonify(ok=True)
    return jsonify({k: SELFTEST[k] for k in ("running", "deep", "step", "results", "finished")})


@app.route("/api/logs")
def api_logs():
    return jsonify(lines=list(VPN.log)[-300:])


# --------------------------------------------------------------------------
# Self-test
# --------------------------------------------------------------------------
SELFTEST = {"running": False, "deep": False, "step": "", "results": [], "finished": 0.0}
_selftest_lock = threading.Lock()
LEAK_V6_ADDR = ("2606:4700:4700::1111", 53)


def _add(results, cid, name, status, detail, fix=""):
    results.append({"id": cid, "name": name, "status": status, "detail": detail, "fix": fix})
    SELFTEST["results"] = list(results)


def _cap_net_admin():
    try:
        with open("/proc/self/status") as f:
            for line in f:
                if line.startswith("CapEff:"):
                    return bool(int(line.split()[1], 16) & (1 << 12))
    except OSError:
        pass
    return False


def _http_target():
    u = urllib.parse.urlparse(IP_CHECK_URL)
    return u.hostname or "api.ipify.org", u.path or "/"


def fetch_ip(ip=None, device=None, timeout=5):
    """Ask the IP-lookup site for our address over plain HTTP, optionally forcing a network interface."""
    host, path = _http_target()
    ip = ip or socket.gethostbyname(host)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        if device:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, device.encode())
        s.connect((ip, 80))
        s.sendall(("GET %s HTTP/1.0\r\nHost: %s\r\nUser-Agent: barrier\r\n\r\n" % (path, host)).encode())
        data = b""
        while len(data) < 2048:
            chunk = s.recv(512)
            if not chunk:
                break
            data += chunk
    finally:
        s.close()
    body = data.split(b"\r\n\r\n", 1)[-1].decode(errors="replace").strip()
    if not re.match(r"^[0-9a-fA-F:.]{3,45}$", body):
        raise ValueError("unexpected reply from IP lookup site")
    return body


def _direct_device():
    """The network card the NAS uses to reach the router (ignoring the VPN tunnel)."""
    try:
        out = subprocess.run(["ip", "route", "show", "default"], capture_output=True, text=True, timeout=5).stdout
    except (OSError, subprocess.TimeoutExpired):
        return None
    for line in out.splitlines():
        m = re.search(r"dev (\S+)", line)
        if m and not m.group(1).startswith("tun"):
            return m.group(1)
    return None


def _v6_leaks():
    try:
        s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        s.settimeout(3)
        s.connect(LEAK_V6_ADDR)
        s.close()
        return True
    except OSError:
        return False


def run_quick_checks(results):
    s = load_settings()
    st = VPN.status()
    connected = st["state"] == "connected"

    # --- setup checks -----------------------------------------------------
    if os.path.exists("/dev/net/tun"):
        try:
            fd = os.open("/dev/net/tun", os.O_RDWR)
            os.close(fd)
            _add(results, "tun", "TUN device", "pass", "The VPN tunnel device is available.")
        except OSError as e:
            _add(results, "tun", "TUN device", "fail", "The tunnel device exists but can't be opened (%s)." % e.strerror,
                 "Stop and run Barrier again in Package Center. If it stays red, send the 'TUN' lines from Container Manager → Container → barrier → Log.")
    else:
        _add(results, "tun", "TUN device", "fail", "The tunnel device is missing, so the VPN can't start.",
             "Barrier switches the tunnel device on when it starts. Stop and run Barrier again in Package Center, then send the 'TUN' lines from Container Manager → Container → barrier → Log if it's still missing.")

    if _cap_net_admin():
        _add(results, "cap", "Network permission", "pass", "The container is allowed to manage network settings.")
    else:
        _add(results, "cap", "Network permission", "fail", "The container isn't allowed to change network settings.",
             "Make sure docker-compose.yml has 'cap_add: NET_ADMIN', then restart the project.")

    try:
        v = subprocess.run([OPENVPN_BIN, "--version"], capture_output=True, text=True, timeout=10).stdout.splitlines()[0]
        _add(results, "openvpn", "OpenVPN program", "pass", v[:60])
    except (OSError, IndexError, subprocess.TimeoutExpired):
        _add(results, "openvpn", "OpenVPN program", "fail", "OpenVPN isn't installed in the container.",
             "Rebuild the project in Container Manager (Project → Action → Build).")

    if not FW.available:
        _add(results, "firewall", "Firewall tools", "warn", "The NAS doesn't let the container edit firewall rules, so the kill switch can't work.",
             "The VPN still works. Avoid attaching other apps to it unless you're OK with them leaking if the VPN drops.")
    elif not s["kill_switch"]:
        _add(results, "firewall", "Kill switch", "warn", "The kill switch is turned off.", "Turn it on in Settings.")
    else:
        ok = DRY_FIREWALL or (subprocess.run([FW.bin4, "-w", "-C", "OUTPUT", "-j", CHAIN], capture_output=True).returncode == 0)
        if ok:
            _add(results, "firewall", "Kill switch rules", "pass", "The kill switch is on and its rules are in place.")
        else:
            _add(results, "firewall", "Kill switch rules", "fail", "The kill switch is on but its rules aren't active.",
                 "Toggle the kill switch off and on in Settings, then run the test again.")

    if os.path.exists(AUTH_FILE):
        with open(AUTH_FILE) as f:
            lines = [l for l in f.read().split("\n") if l.strip()]
        if len(lines) >= 2:
            _add(results, "creds", "ExpressVPN login", "pass", "A username and password are saved.")
        else:
            _add(results, "creds", "ExpressVPN login", "fail", "The saved login looks incomplete.", "Enter the username and password again.")
    else:
        _add(results, "creds", "ExpressVPN login", "fail", "No username/password saved yet.", "Enter them in the ExpressVPN account box.")

    files = sorted(f for f in os.listdir(CONFIGS_DIR) if f.lower().endswith(".ovpn")) if os.path.isdir(CONFIGS_DIR) else []
    if not files:
        _add(results, "files", "Location files", "fail", "No locations have been added.", "Drop your .ovpn files into the Add locations box.")
    else:
        bad = []
        for fn in files:
            try:
                with open(os.path.join(CONFIGS_DIR, fn), errors="replace") as f:
                    text = f.read()
                _, remotes, _ = sanitize_ovpn(text)
                if not remotes or "<ca>" not in text:
                    bad.append(fn)
            except OSError:
                bad.append(fn)
        if bad:
            _add(results, "files", "Location files", "warn", "%d of %d files look damaged (e.g. %s)." % (len(bad), len(files), bad[0]),
                 "Download those locations again from ExpressVPN and re-add them.")
        else:
            _add(results, "files", "Location files", "pass", "%d location file(s), all readable." % len(files))

    if page_password():
        _add(results, "ui", "Web page password", "pass", "The page is password-protected.")
    else:
        _add(results, "ui", "Web page password", "warn", "Anyone on your home network can open this page.",
             "Optional: set a page password in Settings.")

    try:
        socket.gethostbyname("expressvpn.com")
        _add(results, "dns", "Name lookups (DNS)", "pass", "Websites' names can be looked up.")
    except OSError:
        _add(results, "dns", "Name lookups (DNS)", "fail", "Name lookups aren't working.",
             "If the VPN is connected, try another location. If not, check the NAS's own internet connection.")

    last = s.get("last_config")
    if last and os.path.exists(os.path.join(CONFIGS_DIR, last)):
        try:
            with open(os.path.join(CONFIGS_DIR, last), errors="replace") as f:
                host = sanitize_ovpn(f.read())[1][0][0]
            socket.gethostbyname(host)
            _add(results, "server", "VPN server address", "pass", "%s's server address was found." % location_name_for_file(last))
        except (OSError, IndexError):
            _add(results, "server", "VPN server address", "fail", "Couldn't find the VPN server's address.",
                 "Check the NAS's internet connection, or try a different location.")

    # --- live checks (only when connected) -------------------------------
    if not connected:
        _add(results, "live", "Live connection tests", "skip", "Connect to a location first to run the tunnel and leak tests.")
        return

    rx, tx = VPN.counters()
    if os.path.exists("/sys/class/net/%s" % TUN_DEV):
        _add(results, "tunnel", "Tunnel interface", "pass", "The VPN tunnel is up (%s received, %s sent)." % (_fmt_bytes(rx), _fmt_bytes(tx)))
    else:
        _add(results, "tunnel", "Tunnel interface", "fail", "The VPN says it's connected but the tunnel doesn't exist.", "Disconnect and connect again.")

    vpn_ip = None
    try:
        vpn_ip = fetch_ip()
        _add(results, "vpnip", "Internet through the VPN", "pass", "The internet sees you as %s." % vpn_ip)
    except Exception as e:
        _add(results, "vpnip", "Internet through the VPN", "fail", "Connected, but nothing loads through the tunnel (%s)." % e,
             "Try another location or the TCP switch.")

    dev = _direct_device()
    if not dev:
        _add(results, "direct", "Direct-route leak test", "skip", "Couldn't work out the NAS's normal network card.")
    else:
        try:
            host, _ = _http_target()
            direct = fetch_ip(ip=socket.gethostbyname(host), device=dev, timeout=4)
            if vpn_ip and direct == vpn_ip:
                _add(results, "direct", "Direct-route leak test", "fail", "Your IP didn't change: traffic isn't really going through the VPN.",
                     "Disconnect, reconnect, and run the test again.")
            elif s["kill_switch"] and FW.available:
                _add(results, "direct", "Direct-route leak test", "fail", "Traffic got out around the VPN (real IP %s) even though the kill switch is on." % direct,
                     "Toggle the kill switch off and on, then run the test again.")
            else:
                _add(results, "direct", "Direct-route leak test", "warn", "The VPN works, but without the kill switch traffic could escape your real IP (%s) if it drops." % direct,
                     "Turn the kill switch on in Settings.")
        except OSError:
            _add(results, "direct", "Direct-route leak test", "pass", "Traffic can't go around the VPN. Your real IP stays hidden.")
        except Exception as e:
            _add(results, "direct", "Direct-route leak test", "skip", "Couldn't run this test (%s)." % e)

    # DNS leak: resolv.conf should hold the VPN's DNS, and it should be reached through the tunnel
    try:
        with open("/etc/resolv.conf") as f:
            ns = re.findall(r"^nameserver\s+(\S+)", f.read(), re.M)
        vpn_dns = []
        try:
            with open("/tmp/barrier-resolv.vpn") as f:
                vpn_dns = re.findall(r"^nameserver\s+(\S+)", f.read(), re.M)
        except OSError:
            pass
        if ns and set(ns) <= set(vpn_dns):
            route = subprocess.run(["ip", "route", "get", ns[0]], capture_output=True, text=True, timeout=5).stdout
            if "dev %s" % TUN_DEV in route:
                _add(results, "dnsleak", "DNS leak test", "pass", "Name lookups go through the VPN (%s)." % ns[0])
            else:
                _add(results, "dnsleak", "DNS leak test", "warn", "The VPN's DNS server is set, but lookups may not go through the tunnel.", "Disconnect and reconnect.")
        else:
            _add(results, "dnsleak", "DNS leak test", "warn", "The container isn't using the VPN's DNS (using %s)." % (", ".join(ns) or "none"),
                 "Disconnect and reconnect. If it persists, tell me the Connection log.")
    except (OSError, subprocess.TimeoutExpired):
        _add(results, "dnsleak", "DNS leak test", "skip", "Couldn't read the DNS settings.")

    if _v6_leaks():
        _add(results, "ipv6", "IPv6 leak test", "fail", "IPv6 traffic is getting out around the VPN.",
             "Turn off IPv6 on the NAS (Control Panel → Network → Network Interface → Edit → IPv6: Off), then reboot.")
    else:
        _add(results, "ipv6", "IPv6 leak test", "pass", "No IPv6 traffic escapes.")


def _fmt_bytes(n):
    for u in ("B", "KB", "MB", "GB"):
        if n < 1024 or u == "GB":
            return "%d %s" % (n, u) if u == "B" else "%.1f %s" % (n, u)
        n /= 1024.0


def run_drop_test(results):
    """Kill the VPN process on purpose and make sure nothing leaks, then make sure it recovers."""
    host, _ = _http_target()
    try:
        ip = socket.gethostbyname(host)
    except OSError:
        _add(results, "drop", "Kill-switch drop test", "fail", "Couldn't look up the test site, so the test can't run.")
        return
    SELFTEST["step"] = "Dropping the VPN connection on purpose…"
    with VPN.lock:
        proc = VPN.proc
        if not proc or VPN.state != "connected":
            _add(results, "drop", "Kill-switch drop test", "skip", "Not connected, so there was nothing to drop.")
            return
        proc.kill()
    time.sleep(1.0)
    SELFTEST["step"] = "VPN is down. Checking that nothing escapes…"
    leaked = None
    try:
        leaked = fetch_ip(ip=ip, timeout=4)
    except OSError:
        pass
    except ValueError:
        pass
    if leaked:
        _add(results, "drop", "Traffic while VPN is down", "fail", "While the VPN was down, traffic still got out (your real IP: %s)." % leaked,
             "The kill switch isn't protecting you. Toggle it off and on and test again.")
    else:
        _add(results, "drop", "Traffic while VPN is down", "pass", "With the VPN down, no traffic escaped. The kill switch held.")
    SELFTEST["step"] = "Waiting for the VPN to reconnect by itself…"
    t0 = time.time()
    while time.time() - t0 < 90:
        if VPN.state == "connected":
            break
        if VPN.state in ("auth_failed", "error", "disconnected"):
            break
        time.sleep(1)
    if VPN.state == "connected":
        _add(results, "recover", "Automatic reconnect", "pass", "The VPN reconnected on its own in about %d seconds." % int(time.time() - t0))
        time.sleep(2)
        try:
            _add(results, "recover2", "Internet after reconnect", "pass", "Back online as %s." % fetch_ip())
        except Exception as e:
            _add(results, "recover2", "Internet after reconnect", "warn", "Reconnected but the internet check failed (%s). Try again in a moment." % e)
    else:
        _add(results, "recover", "Automatic reconnect", "fail", "The VPN did not come back within 90 seconds (state: %s)." % VPN.state,
             "Open the Connection log. You can also press Connect to retry.")


def _selftest_worker(deep):
    results = []
    SELFTEST.update(running=True, deep=deep, step="Running checks…", results=[], finished=0.0)
    try:
        run_quick_checks(results)
        if deep:
            run_drop_test(results)
    except Exception as e:  # never leave the page hanging
        _add(results, "internal", "Test runner", "fail", "The test itself crashed: %s" % e)
    finally:
        SELFTEST.update(running=False, step="", finished=time.time())



# --------------------------------------------------------------------------
# Updates: check GitHub, download the new app, check it, restart into it.
# Only the app (this Python program and its page) is swapped; the container,
# and Lifestream inside its network, keep running.
# --------------------------------------------------------------------------
def _vtuple(v):
    return tuple(int(x) for x in re.findall(r"\d+", v or "")[:4]) or (0,)


def is_newer(a, b):
    return _vtuple(a) > _vtuple(b)



def plain_update_error(e):
    """A short message for a failed check or download that never names the server."""
    if isinstance(e, ValueError):
        return str(e)
    if isinstance(e, urllib.error.HTTPError):
        return "the update server answered with an error (HTTP %d). Try again later." % e.code
    if isinstance(e, (TimeoutError, socket.timeout)):
        return "the update server took too long to answer. Try again later."
    return "couldn't reach the update server. Check the internet connection and try again."

class Updater:
    def __init__(self):
        self.lock = threading.Lock()
        self.latest = None        # {"version", "notes", "url", "sha256", "size"}
        self.checked_at = 0
        self.error = ""
        self.checking = False
        self.progress = None      # {"phase", "done", "total", "message"}
        self.installing = False
        self.result = self._read_result()

    @staticmethod
    def _result_path():
        return os.path.join(CONFIG_DIR, "update-result.json")

    def _read_result(self):
        try:
            with open(self._result_path()) as f:
                return json.load(f)
        except (OSError, ValueError):
            return None

    def _write_result(self, ok, to, message):
        self.result = {"ok": ok, "from": VERSION, "to": to, "message": message, "time": int(time.time())}
        try:
            with open(self._result_path(), "w") as f:
                json.dump(self.result, f)
        except OSError:
            pass

    def check(self):
        with self.lock:
            if self.checking:
                return
            self.checking = True
        try:
            req = urllib.request.Request(RELEASE_URL, headers={"User-Agent": "Barrier/" + VERSION, "Accept": "application/vnd.github+json"})
            with urllib.request.urlopen(req, timeout=20) as r:
                j = json.load(r)
            version = str(j.get("tag_name", "")).lstrip("v")
            asset = next((a for a in j.get("assets", []) if re.fullmatch(r"barrier-app-[\w.]+\.tar\.gz", a.get("name", ""))), None)
            if not version or not asset:
                raise ValueError("The newest release has no Barrier app download")
            digest = str(asset.get("digest") or "")
            self.latest = {"version": version, "notes": j.get("body") or "", "url": asset.get("browser_download_url", ""),
                           "sha256": digest[7:].lower() if digest.startswith("sha256:") else "", "size": int(asset.get("size") or 0)}
            self.error = ""
        except Exception as e:  # network down, VPN disconnected with the kill switch on, server busy
            self.error = "Couldn't check for updates: " + plain_update_error(e)
        finally:
            self.checked_at = int(time.time())
            self.checking = False

    def available(self):
        return bool(self.latest and is_newer(self.latest["version"], VERSION))

    def status(self):
        return {"current": VERSION, "latest": self.latest["version"] if self.latest else "", "notes": self.latest["notes"] if self.latest else "",
                "available": self.available(), "checked_at": self.checked_at, "checking": self.checking, "error": self.error,
                "can_install": bool(UPDATE_DIR), "installing": self.installing, "progress": self.progress, "last_result": self.result,
                "auto_update": load_settings()["auto_update"]}

    def start_install(self):
        if not UPDATE_DIR:
            return "This copy of Barrier wasn't started by its package, so it can't install updates by itself. Reinstall Barrier from its Synology package once to turn updates on."
        if not self.available():
            return "There's no newer version to install."
        with self.lock:
            if self.installing:
                return "An update is already running."
            self.installing = True
        self.progress = {"phase": "download", "done": 0, "total": self.latest["size"], "message": ""}
        threading.Thread(target=self._install, args=(dict(self.latest),), daemon=True).start()
        return ""

    def _install(self, rel):
        work = os.path.join(UPDATE_DIR, "work")
        try:
            shutil.rmtree(work, ignore_errors=True)
            os.makedirs(work)
            if not rel["sha256"]:
                raise ValueError("The update server didn't give a checksum for the download, so it wasn't installed.")
            tgz = os.path.join(work, "app.tar.gz")
            h = hashlib.sha256()
            req = urllib.request.Request(rel["url"], headers={"User-Agent": "Barrier/" + VERSION})
            with urllib.request.urlopen(req, timeout=60) as r, open(tgz, "wb") as f:
                done = 0
                while True:
                    chunk = r.read(65536)
                    if not chunk:
                        break
                    f.write(chunk)
                    h.update(chunk)
                    done += len(chunk)
                    self.progress = {"phase": "download", "done": done, "total": rel["size"], "message": ""}
            self.progress = {"phase": "verify", "done": 1, "total": 1, "message": ""}
            if h.hexdigest() != rel["sha256"]:
                raise ValueError("The download didn't match its checksum. Nothing was changed.")
            staged = os.path.join(work, "staged")
            os.makedirs(staged)
            with tarfile.open(tgz) as t:
                for m in t.getmembers():
                    name = os.path.normpath(m.name)
                    if name.startswith("..") or os.path.isabs(name) or not (m.isfile() or m.isdir()):
                        raise ValueError("The download has an unexpected file in it (%s). Nothing was changed." % m.name)
                try:
                    t.extractall(staged, filter="data")
                except TypeError:  # Python without extraction filters
                    t.extractall(staged)
            root = os.path.join(staged, "app")
            try:
                with open(os.path.join(root, "VERSION")) as f:
                    got = f.read().strip()
            except OSError:
                got = ""
            if got != rel["version"] or not os.path.isfile(os.path.join(root, "app.py")):
                raise ValueError("The download isn't the version that was offered. Nothing was changed.")
            compile(open(os.path.join(root, "app.py")).read(), "app.py", "exec")
            nxt = os.path.join(UPDATE_DIR, "next")
            shutil.rmtree(nxt, ignore_errors=True)
            os.rename(root, nxt)
            self._write_result(True, rel["version"], "Updated to %s" % rel["version"])
            self.progress = {"phase": "restart", "done": 1, "total": 1, "message": ""}
            VPN._log("Update %s downloaded; restarting Barrier into it" % rel["version"])
            time.sleep(2)  # let the page show "Restarting"
            restart_for_update()
        except Exception as e:
            msg = plain_update_error(e)
            msg = msg[0].upper() + msg[1:]
            self._write_result(False, rel["version"], msg)
            self.progress = {"phase": "failed", "done": 0, "total": 0, "message": msg}
            VPN._log("Update failed: %s" % msg)
            with self.lock:
                self.installing = False
        finally:
            shutil.rmtree(work, ignore_errors=True)

    def loop(self):
        """Check a minute after start, then every 6 hours; install by itself when that's turned on."""
        time.sleep(60)
        while True:
            self.check()
            if self.available() and load_settings()["auto_update"] and UPDATE_DIR and not self.installing:
                VPN._log("Installing update %s automatically" % self.latest["version"])
                self.start_install()
            time.sleep(6 * 3600)


UPD = Updater()
RECONNECT_FILE = os.path.join(CONFIG_DIR, "reconnect-after-update")


def restart_for_update():
    """Remember the location if connected, disconnect cleanly (the kill switch stays up), exit for the swap."""
    try:
        with VPN.lock:
            if VPN.current:
                with open(RECONNECT_FILE, "w") as f:
                    f.write(VPN.current)
        VPN.disconnect()
    finally:
        os._exit(UPDATE_EXIT)


@app.route("/api/update")
def api_update():
    return jsonify(UPD.status())


@app.route("/api/update/check", methods=["POST"])
def api_update_check():
    UPD.check()
    return jsonify(UPD.status())


@app.route("/api/update/install", methods=["POST"])
def api_update_install():
    msg = UPD.start_install()
    if msg:
        return err(msg)
    return jsonify(UPD.status())

# --------------------------------------------------------------------------
# Startup
# --------------------------------------------------------------------------
def shutdown(*_):
    try:
        VPN.disconnect()
    finally:
        os._exit(0)


def boot():
    s = load_settings()
    if s["kill_switch"]:
        ports = set()
        fn = s.get("last_config")
        if fn and os.path.exists(os.path.join(CONFIGS_DIR, fn)):
            try:
                with open(os.path.join(CONFIGS_DIR, fn), errors="replace") as f:
                    ports = {(rp, p) for _, p, rp in sanitize_ovpn(f.read())[1]}
            except OSError:
                pass
        FW.apply(s["lan_subnets"], ports)
    threading.Thread(target=VPN.watchdog, daemon=True).start()
    fn = s.get("last_config")
    # Back from an update: reconnect to where it was, whether or not auto-connect is on.
    try:
        with open(RECONNECT_FILE) as f:
            back = f.read().strip()
        os.remove(RECONNECT_FILE)
    except OSError:
        back = ""
    if back and os.path.exists(os.path.join(CONFIGS_DIR, back)) and os.path.exists(AUTH_FILE):
        VPN._log("Back from the update; reconnecting")
        VPN.connect(back)
    elif s["auto_connect"] and fn and os.path.exists(os.path.join(CONFIGS_DIR, fn)) and os.path.exists(AUTH_FILE):
        VPN.connect(fn)
    threading.Thread(target=UPD.loop, daemon=True).start()


if __name__ == "__main__":
    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)
    boot()
    try:
        from waitress import serve
        serve(app, host="0.0.0.0", port=PORT, threads=8)
    except ImportError:
        app.run(host="0.0.0.0", port=PORT, threaded=True)
