#!/usr/bin/env python3
"""Automated tests for Barrier. Needs only Python 3 + Flask (already in the container).

    python3 tests/run_tests.py

Starts the app against a fake OpenVPN, so nothing real is touched.
These tests prove the app's logic. They can't prove your NAS is set up right:
for that, use the Self-test card in the web page.
"""
import base64, io, json, os, shutil, signal, subprocess, sys, tempfile, time, traceback, urllib.error, urllib.request, zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
APP_DIR = os.path.join(os.path.dirname(HERE), "app")
MOCK = os.path.join(HERE, "mock_openvpn.sh")
PORT = 8197
PW = "sekret"

TMP = tempfile.mkdtemp(prefix="nasvpn-test-")
CFG = os.path.join(TMP, "config")
RUNTIME = os.path.join(TMP, "runtime.ovpn")
LAUNCH_LOG = os.path.join(TMP, "launches.log")
os.makedirs(CFG)

ENV = dict(os.environ, CONFIG_DIR=CFG, OPENVPN_BIN=MOCK, DRY_RUN_FIREWALL="1", UI_PASSWORD=PW, PORT=str(PORT),
           RUNTIME_CFG=RUNTIME, MOCK_LAUNCH_LOG=LAUNCH_LOG, SCRIPT_DIR=os.path.join(APP_DIR, "scripts"),
           IP_CHECK_URL="http://127.0.0.1:9/",  # nothing listens there: network checks fail fast
           DNS_CHECK_NAMES="nothing.invalid", NO_INTERNET_RECONNECT="0")

CERT = "<ca>\n-----BEGIN CERTIFICATE-----\nup /inside/block/stays\n-----END CERTIFICATE-----\n</ca>\n"


def ovpn(host="usa-new-york.example.net", proto="udp", port=1195, extra=""):
    return ("client\ndev tun\nproto %s\nremote %s %d\nup /bin/evil.sh\nscript-security 3\nroute-method exe\n"
            "plugin /lib/evil.so\nauth-user-pass\ncipher AES-256-CBC\n%s%s") % (proto, host, port, extra, CERT)


# ---------------------------------------------------------------- tiny test framework
RESULTS = []


def test(fn):
    RESULTS.append(fn)
    return fn


# ---------------------------------------------------------------- server helpers
class Server:
    def __init__(self, env=None):
        self.env = env or ENV
        self.proc = None

    def start(self):
        self.proc = subprocess.Popen([sys.executable, "-I", os.path.join(APP_DIR, "app.py")], cwd=APP_DIR, env=self.env,
                                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for _ in range(60):
            try:
                urllib.request.urlopen("http://127.0.0.1:%d/api/health" % PORT, timeout=1)
                return
            except Exception:
                time.sleep(0.25)
        raise RuntimeError("server did not start")

    def stop(self):
        if self.proc:
            self.proc.send_signal(signal.SIGTERM)
            try:
                self.proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.proc.kill()
            self.proc = None


def call(path, method="GET", body=None, auth=True, csrf=True, raw=None, ctype="application/json", pw=PW):
    headers = {}
    if auth:
        headers["Authorization"] = "Basic " + base64.b64encode(("x:" + pw).encode()).decode()
    if csrf:
        headers["X-Requested-With"] = "barrier"
    data = raw
    if body is not None:
        data = json.dumps(body).encode()
    if data is not None:
        headers["Content-Type"] = ctype
    req = urllib.request.Request("http://127.0.0.1:%d%s" % (PORT, path), data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read() or b"{}")
        except ValueError:
            return e.code, {}


def multipart(files):
    boundary = "----nasvpntest"
    out = io.BytesIO()
    for name, data in files:
        out.write(("--%s\r\nContent-Disposition: form-data; name=\"files\"; filename=\"%s\"\r\n"
                   "Content-Type: application/octet-stream\r\n\r\n" % (boundary, name)).encode())
        out.write(data if isinstance(data, bytes) else data.encode())
        out.write(b"\r\n")
    out.write(("--%s--\r\n" % boundary).encode())
    return out.getvalue(), "multipart/form-data; boundary=" + boundary


def upload(files):
    raw, ct = multipart(files)
    return call("/api/upload", "POST", raw=raw, ctype=ct)


def wait_state(want, timeout=12):
    end = time.time() + timeout
    while time.time() < end:
        st = call("/api/status")[1]
        if st["state"] in want:
            return st
        time.sleep(0.3)
    return call("/api/status")[1]


def run_selftest(deep=False, timeout=60):
    code, body = call("/api/selftest", "POST", {"deep": deep})
    if code != 200:
        return code, body
    end = time.time() + timeout
    while time.time() < end:
        t = call("/api/selftest")[1]
        if not t["running"]:
            return 200, t
        time.sleep(0.5)
    raise AssertionError("self-test never finished")


def launches():
    try:
        return len(open(LAUNCH_LOG).read().split())
    except OSError:
        return 0


def check(cond, msg=""):
    if not cond:
        raise AssertionError(msg or "check failed")


# ================================================================ UNIT TESTS (import the app directly)
sys.path.insert(0, APP_DIR)
os.environ.update(ENV)
import app as A  # noqa: E402


@test
def unit_sanitize_strips_dangerous_directives():
    clean, remotes, proto = A.sanitize_ovpn(ovpn())
    lines = [l.strip() for l in clean.split("\n")]
    for bad in ("up /bin/evil.sh", "script-security 3", "route-method exe", "plugin /lib/evil.so", "auth-user-pass"):
        check(bad not in lines, "directive not stripped: " + bad)
    check("up /inside/block/stays" in lines, "content inside <ca> block must be preserved")
    check("cipher AES-256-CBC" in lines)


@test
def unit_sanitize_extracts_remotes():
    _, remotes, proto = A.sanitize_ovpn(ovpn(host="h.example", proto="tcp", port=443))
    check(remotes == [("h.example", 443, "tcp")], remotes)
    check(proto == "tcp")


@test
def unit_location_names():
    check(A.pretty_location("my_expressvpn_usa_-_new_york_udp.ovpn")[1:] == ("USA - New York", "USA", "udp"))
    check(A.pretty_location("my_expressvpn_uk_-_london_tcp.ovpn")[1:] == ("UK - London", "UK", "tcp"))
    check(A.pretty_location("my_expressvpn_new_zealand_udp.ovpn")[1] == "New Zealand")
    check(A.pretty_location("my_expressvpn_japan_-_tokyo_udp.ovpn")[0] == A.pretty_location("my_expressvpn_japan_-_tokyo_tcp.ovpn")[0],
          "UDP and TCP of one place must share a key")


@test
def unit_filename_safety():
    check(A.safe_filename("../../etc/passwd") is None)
    check(A.safe_filename("notes.txt") is None)
    check(A.safe_filename("../../evil.ovpn") == "evil.ovpn")
    check("/" not in A.safe_filename("a/b/c.ovpn"))


@test
def unit_subnet_validation():
    check(A.clean_subnets(["192.168.1.5/16"]) == ["192.168.0.0/16"])
    for bad in (["nonsense"], ["fe80::/10"], ["300.1.1.1/8"]):
        try:
            A.clean_subnets(bad)
        except ValueError:
            continue
        raise AssertionError("accepted bad subnet %r" % bad)


@test
def unit_firewall_rules():
    A.FW.rules_log.clear()
    A.FW.apply(["192.168.0.0/16"], {("udp", 1195)})
    rules = A.FW.rules_log
    chain = [r for r in rules if r.startswith("iptables -A NASVPN_KS")]
    check(chain[-1].endswith("-j DROP"), "chain must end with DROP")
    check(any("-o tun+ -j ACCEPT" in r for r in chain), "tunnel traffic must be allowed")
    check(any("-d 192.168.0.0/16" in r for r in chain), "LAN must be allowed")
    check(any("-p udp --dport 1195" in r for r in chain), "VPN handshake port must be allowed")
    check(any(r.startswith("ip6tables") and r.endswith("-j DROP") for r in rules), "IPv6 must be blocked")
    A.FW.rules_log.clear()
    A.FW.clear()
    check(any("-X NASVPN_KS" in r for r in A.FW.rules_log), "clear must delete the chain")


@test
def unit_runtime_config():
    fn = os.path.join(A.CONFIGS_DIR, "unit.ovpn")
    open(fn, "w").write(ovpn())
    A.save_settings(dict(A._default_settings(), lan_subnets=["192.168.0.0/16"]))
    ports = A.VPN._prepare("unit.ovpn")
    text = open(RUNTIME).read()
    check(ports == {("udp", 1195)}, ports)
    check("route 192.168.0.0 255.255.0.0 net_gateway" in text, "LAN must bypass the tunnel")
    check("redirect-gateway def1" in text)
    check("up /bin/evil.sh" not in text and "plugin /lib/evil.so" not in text, "dangerous lines leaked into runtime config")
    check(oct(os.stat(RUNTIME).st_mode & 0o777) == "0o600", "runtime config must be private")
    os.remove(fn)
    A.save_settings(A._default_settings())


# ================================================================ API / BEHAVIOUR TESTS
@test
def api_requires_password():
    check(call("/api/status", auth=False)[0] == 401)
    check(call("/api/status", pw="wrong")[0] == 401)
    check(call("/api/status")[0] == 200)
    check(call("/api/health", auth=False)[0] == 200, "health check must work without a password")


@test
def api_blocks_cross_site_posts():
    check(call("/api/disconnect", "POST", {}, csrf=False)[0] == 403)


@test
def api_connect_needs_credentials():
    code, body = call("/api/connect", "POST", {"key": "x"})
    check(code == 400 and "username" in body["error"].lower(), body)


@test
def api_credentials_saved_privately():
    check(call("/api/credentials", "POST", {"username": "", "password": "p"})[0] == 400)
    check(call("/api/credentials", "POST", {"username": "u\nx", "password": "p"})[0] == 400)
    check(call("/api/credentials", "POST", {"username": "user1", "password": "pass1"})[0] == 200)
    mode = os.stat(os.path.join(CFG, "auth.txt")).st_mode & 0o777
    check(mode == 0o600, oct(mode))
    body = call("/api/credentials")[1]
    check(body == {"has": True, "username": "user1"}, "password must never be sent back to the browser")


@test
def api_upload_files_and_zip():
    code, body = upload([("my_expressvpn_usa_-_new_york_udp.ovpn", ovpn()),
                         ("my_expressvpn_usa_-_new_york_tcp.ovpn", ovpn(proto="tcp", port=443)),
                         ("notes.txt", "hello"), ("garbage.ovpn", "no remote line here")])
    check(code == 200 and body["saved"] == 2, body)
    check("garbage.ovpn" in body["skipped"])
    z = io.BytesIO()
    with zipfile.ZipFile(z, "w") as zf:
        zf.writestr("my_expressvpn_uk_-_london_udp.ovpn", ovpn(host="uk.example.net"))
        zf.writestr("../../escape.ovpn", ovpn())
        zf.writestr("readme.txt", "x")
    code, body = upload([("pack.zip", z.getvalue())])
    check(code == 200 and body["saved"] == 2, (body, sorted(os.listdir(os.path.join(CFG, "configs")))))
    check(not os.path.exists(os.path.join(TMP, "escape.ovpn")) and not os.path.exists("/tmp/escape.ovpn"), "zip path traversal!")
    check(os.path.exists(os.path.join(CFG, "configs", "escape.ovpn")), "flattened name should be inside configs/")
    os.remove(os.path.join(CFG, "configs", "escape.ovpn"))
    locs = call("/api/locations")[1]["locations"]
    ny = [l for l in locs if l["key"] == "usa_-_new_york"][0]
    check(ny["protocols"] == ["tcp", "udp"], ny)
    check(os.path.exists(os.path.join(CFG, "configs", "my_expressvpn_usa_-_new_york_udp.ovpn")))


@test
def api_settings_validation():
    check(call("/api/settings", "POST", {"lan_subnets": "garbage"})[0] == 400)
    code, body = call("/api/settings", "POST", {"lan_subnets": "192.168.1.0/24, 10.1.0.0/16"})
    check(code == 200 and body["lan_subnets"] == ["192.168.1.0/24", "10.1.0.0/16"], body)
    call("/api/settings", "POST", {"lan_subnets": "192.168.0.0/16,172.16.0.0/12,10.0.0.0/8"})


@test
def vpn_connect_and_protocol_choice():
    check(call("/api/connect", "POST", {"key": "usa_-_new_york", "protocol": "tcp"})[1].get("protocol") == "tcp")
    st = wait_state({"connected"})
    check(st["state"] == "connected" and st["location"] == "USA - New York", st)
    text = open(RUNTIME).read()
    check("proto tcp" in text and " 443" in text, "TCP file should have been used")
    check("evil" not in text, "dangerous directive reached OpenVPN")
    check(call("/api/connect", "POST", {"key": "usa_-_new_york", "protocol": "udp"})[1]["protocol"] == "udp")
    wait_state({"connected"})
    check("proto udp" in open(RUNTIME).read())
    check(call("/api/connect", "POST", {"key": "nowhere"})[0] == 404)


@test
def vpn_cannot_clear_while_connected():
    check(call("/api/configs/clear", "POST", {})[0] == 400)


@test
def vpn_disconnect_stops_process():
    check(call("/api/disconnect", "POST", {})[0] == 200)
    check(wait_state({"disconnected"})["state"] == "disconnected")
    time.sleep(1.5)
    out = subprocess.run(["pgrep", "-f", "^/bin/sh " + MOCK], capture_output=True, text=True).stdout.strip()
    check(not out, "OpenVPN process still running after disconnect: " + out)


@test
def vpn_bad_login_stops_retrying():
    open(os.path.join(CFG, "configs", "my_expressvpn_badauth_-_x_udp.ovpn"), "w").write(ovpn(extra="verb 3 BADAUTH\n"))
    call("/api/connect", "POST", {"key": "badauth_-_x"})
    st = wait_state({"auth_failed"})
    check(st["state"] == "auth_failed" and "rejected" in st["message"], st)
    n = launches()
    time.sleep(7)
    check(launches() == n, "app kept hammering ExpressVPN with a bad password")
    call("/api/disconnect", "POST", {})


@test
def vpn_retries_after_crash():
    open(os.path.join(CFG, "configs", "my_expressvpn_crash_-_x_udp.ovpn"), "w").write(ovpn(extra="verb 3 CRASH\n"))
    n = launches()
    call("/api/connect", "POST", {"key": "crash_-_x"})
    time.sleep(13)
    check(launches() - n >= 2, "expected automatic retries, launches=%d" % (launches() - n))
    check(call("/api/status")[1]["state"] in ("reconnecting", "connecting"))
    call("/api/disconnect", "POST", {})
    check(wait_state({"disconnected"})["state"] == "disconnected")


@test
def selftest_quick_reports_clearly():
    code, t = run_selftest()
    check(code == 200 and t["results"], t)
    by = {r["id"]: r for r in t["results"]}
    check(by["creds"]["status"] == "pass", by["creds"])
    check(by["files"]["status"] == "pass" or by["files"]["status"] == "warn", by["files"])
    check(by["live"]["status"] == "skip", "live tests must be skipped when not connected")
    for r in t["results"]:
        check(r["status"] in ("pass", "warn", "fail", "skip") and r["name"] and r["detail"], r)
        if r["status"] == "fail":
            check(r["fix"], "every failure needs a 'what to do': " + r["id"])


@test
def selftest_detects_missing_login():
    os.rename(os.path.join(CFG, "auth.txt"), os.path.join(CFG, "auth.bak"))
    try:
        by = {r["id"]: r for r in run_selftest()[1]["results"]}
        check(by["creds"]["status"] == "fail", by["creds"])
    finally:
        os.rename(os.path.join(CFG, "auth.bak"), os.path.join(CFG, "auth.txt"))


@test
def selftest_drop_test_preconditions():
    code, body = call("/api/selftest", "POST", {"deep": True})
    check(code == 400 and "connect" in body["error"].lower(), (code, body))
    call("/api/connect", "POST", {"key": "usa_-_new_york"})
    wait_state({"connected"})
    call("/api/settings", "POST", {"kill_switch": False})
    code, body = call("/api/selftest", "POST", {"deep": True})
    check(code == 400 and "kill switch" in body["error"].lower(), (code, body))
    call("/api/settings", "POST", {"kill_switch": True})


@test
def selftest_runs_while_connected():
    code, t = run_selftest()
    ids = [r["id"] for r in t["results"]]
    check("vpnip" in ids and "direct" in ids and "dnsleak" in ids and "ipv6" in ids, ids)
    call("/api/disconnect", "POST", {})


@test
def autoconnect_after_restart():
    call("/api/connect", "POST", {"key": "usa_-_new_york"})
    wait_state({"connected"})
    call("/api/settings", "POST", {"auto_connect": True})
    call("/api/disconnect", "POST", {})
    SRV.stop(); SRV.start()
    st = wait_state({"connected"}, timeout=15)
    check(st["state"] == "connected", "should reconnect by itself after a restart: %s" % st)
    call("/api/disconnect", "POST", {})


@test
def unit_no_internet_restart_rule():
    sys.path.insert(0, APP_DIR)
    import importlib
    os.environ.setdefault("CONFIG_DIR", CFG)
    app = importlib.import_module("app")
    r = app.needs_restart
    check(not r("connected", 1000, None, 2000, 180), "internet fine: no restart")
    check(not r("connected", 1000, 1900, 2000, 180), "only 100s without internet: too soon")
    check(r("connected", 1000, 1800, 2000, 180), "200s without internet: restart")
    check(not r("connected", 1990, 1800, 2000, 180), "just connected: give it a minute")
    check(not r("reconnecting", 1000, 1000, 2000, 180), "only while connected")
    check(not r("connected", 1000, 1000, 9000, 0), "0 turns it off")


@test
def unit_lifestream_rejoin_spec():
    sys.path.insert(0, APP_DIR)
    import rejoin
    info = {
        "Config": {"Image": "lifestream-package:1", "Hostname": "abc", "ExposedPorts": {"1/tcp": {}},
                   "Env": ["A=1"], "Labels": {"com.docker.compose.project": "lifestream"}},
        "HostConfig": {"NetworkMode": "container:old", "Binds": ["/v:/v"], "PortBindings": {},
                       "RestartPolicy": {"Name": "unless-stopped"}, "Dns": []},
        "State": {"Running": False, "Error": ""},
    }
    spec = rejoin.recreate_spec(info, "new")
    check(spec["HostConfig"]["NetworkMode"] == "container:new", spec)
    check("Hostname" not in spec and "ExposedPorts" not in spec, "network-only fields must go")
    check(spec["Labels"]["com.docker.compose.project"] == "lifestream", "Container Manager must still see the project")
    check(spec["HostConfig"]["Binds"] == ["/v:/v"] and spec["Env"] == ["A=1"], "settings must carry over")
    check(info["HostConfig"]["NetworkMode"] == "container:old", "must not change the original")
    check(not rejoin.should_start(info), "a stopped Lifestream stays stopped")
    check(rejoin.should_start({"State": {"Running": True}}))
    check(rejoin.should_start({"State": {"Running": False, "Error": "joining network namespace of container: No such container: x"}}),
          "one that died because Barrier was replaced gets started")
    old = rejoin.SOCK
    rejoin.SOCK = os.path.join(TMP, "no-such.sock")
    check(rejoin.check() == "no-docker")
    rejoin.SOCK = old


@test
def package_carries_over_old_settings():
    ep = os.path.join(os.path.dirname(HERE), "synology", "entrypoint.sh")
    src = open(ep).read()
    block = src[src.index("# 2. Settings from"):src.index("version() {")]
    base = tempfile.mkdtemp(prefix="mig-", dir=TMP)
    old, conf = os.path.join(base, "old"), os.path.join(base, "conf")

    def w(path, text):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        open(path, "w").write(text)

    def old_project():
        w(os.path.join(old, "barrier", "config", "auth.txt"), "user\npass\n")
        w(os.path.join(old, "barrier", "config", "settings.json"), '{"auto_connect": true, "last_config": "a_udp.ovpn"}')
        w(os.path.join(old, "barrier", "config", "configs", "a_udp.ovpn"), "remote a\n")
        w(os.path.join(old, "barrier", "config", "configs", "b_udp.ovpn"), "remote b\n")
        w(os.path.join(old, "barrier", "docker-compose.yml"), "services:\n  b:\n    environment:\n      - UI_PASSWORD=pw1\n")

    def start():
        return subprocess.run(["sh", "-c", block], env=dict(os.environ, OLDROOT=old, CONF=conf),
                              capture_output=True, text=True).stdout

    def locs():
        d = os.path.join(conf, "configs")
        return sorted(os.listdir(d)) if os.path.isdir(d) else []

    # The NAS's case: a first try died half-way and left empty files and the wrong settings.
    old_project()
    w(os.path.join(conf, "settings.json"), '{"auto_connect": false}')
    w(os.path.join(conf, "auth.txt"), "")
    w(os.path.join(conf, "configs", "a_udp.ovpn"), "")
    out = start()
    check("2 locations, login saved" in out, out)
    check(open(os.path.join(conf, "auth.txt")).readline().strip() == "user")
    check(locs() == ["a_udp.ovpn", "b_udp.ovpn"] and os.path.getsize(os.path.join(conf, "configs", "a_udp.ovpn")) > 0)
    check('"auto_connect": true' in open(os.path.join(conf, "settings.json")).read(), "must reconnect by itself afterwards")
    check(open(os.path.join(conf, "page-password")).read() == "pw1")

    # Locations removed on purpose stay removed after a restart.
    for f in locs():
        os.remove(os.path.join(conf, "configs", f))
    check("Bringing over" not in start() and locs() == [], "removed locations came back")

    # Fresh install next to the old project.
    shutil.rmtree(conf)
    os.makedirs(conf)
    check("2 locations" in start() and len(locs()) == 2)

    # No old project: nothing happens.
    shutil.rmtree(conf)
    shutil.rmtree(old)
    os.makedirs(conf)
    start()
    check(os.listdir(conf) == [], os.listdir(conf))
    shutil.rmtree(base)


@test
def package_status_script():
    script = os.path.join(os.path.dirname(HERE), "synology", "scripts", "start-stop-status")
    flag = "/tmp/.barrier-package-started"
    run = lambda a: subprocess.run(["sh", script, a], capture_output=True).returncode
    try:
        os.remove(flag)
    except OSError:
        pass
    # The test server runs on PORT, not 8085, so the page never "answers" here.
    check(run("status") == 3, "never started: not running")
    check(run("start") == 0 and run("status") == 0, "just started: counts as running while it comes up")
    old = time.time() - 600
    os.utime(flag, (old, old))
    check(run("status") == 3, "started long ago and the page never answered: not running")
    check(run("stop") == 0 and not os.path.exists(flag))


@test
def vpn_restarts_when_connected_without_internet():
    global SRV
    old = SRV
    old.stop()
    SRV = Server(dict(ENV, NO_INTERNET_RECONNECT="4"))
    SRV.start()
    try:
        call("/api/connect", "POST", {"key": "usa_-_new_york"})
        check(wait_state({"connected"})["state"] == "connected")
        n = launches()
        end = time.time() + 40
        while time.time() < end and launches() == n:
            time.sleep(0.5)
        check(launches() > n, "a tunnel with no internet should be restarted")
        st = wait_state({"connected"}, timeout=15)
        check(st["state"] == "connected", "should come back connected to the same place: %s" % st)
        logs = call("/api/logs")[1]
        check("no internet through the VPN" in json.dumps(logs), "log should say why it reconnected")
        call("/api/disconnect", "POST", {})
        wait_state({"disconnected"})
        n = launches()
        time.sleep(8)
        check(launches() == n, "no restarts once disconnected")
    finally:
        SRV.stop()
        SRV = old
        SRV.start()


@test
def page_password_set_and_remove():
    code, j = call("/api/password", "POST", {"password": "newpass1"})
    check(code == 400 and "UI_PASSWORD" in j.get("error", ""), "with UI_PASSWORD set it can't be changed here: %s" % j)
    SRV.stop()
    SRV.env = dict(ENV, UI_PASSWORD="")
    SRV.start()
    check(call("/api/status", auth=False)[0] == 200, "no password: page is open")
    check(call("/api/password", "POST", {"password": "abc"}, auth=False)[0] == 400, "too short is refused")
    check(call("/api/password", "POST", {"password": "newpass1"}, auth=False)[0] == 200, "set it")
    check(call("/api/status", auth=False)[0] == 401, "now it asks for the password")
    check(call("/api/status", pw="wrong")[0] == 401, "wrong password refused")
    st = call("/api/status", pw="newpass1")
    check(st[0] == 200 and st[1]["ui_password"], "right password works")
    mode = oct(os.stat(os.path.join(CFG, "page-password")).st_mode & 0o777)
    check(mode == "0o600", "the password file is private: %s" % mode)
    check(call("/api/password", "POST", {"password": ""}, pw="newpass1")[0] == 200, "remove it")
    check(call("/api/status", auth=False)[0] == 200, "open again")
    SRV.stop()
    SRV.env = ENV
    SRV.start()


# ================================================================ updates
import hashlib, http.server, tarfile, threading

UPD_DIR = os.path.join(TMP, "app-update")
REL_DIR = os.path.join(TMP, "release")
REL_PORT = 8198


def release(version, tamper=False):
    """Publish a fake GitHub release whose app download is this app, labelled `version`."""
    shutil.rmtree(REL_DIR, ignore_errors=True)
    os.makedirs(REL_DIR)
    stage = os.path.join(TMP, "stage")
    shutil.rmtree(stage, ignore_errors=True)
    shutil.copytree(APP_DIR, os.path.join(stage, "app"), ignore=shutil.ignore_patterns("__pycache__"))
    with open(os.path.join(stage, "app", "VERSION"), "w") as f:
        f.write(version + "\n")
    name = "barrier-app-%s.tar.gz" % version
    tgz = os.path.join(REL_DIR, name)
    with tarfile.open(tgz, "w:gz") as t:
        t.add(os.path.join(stage, "app"), arcname="app")
    digest = hashlib.sha256(open(tgz, "rb").read()).hexdigest()
    if tamper:
        digest = "0" * 64
    with open(os.path.join(REL_DIR, "latest.json"), "w") as f:
        json.dump({"tag_name": "v" + version, "body": "- Test release", "assets": [
            {"name": "Barrier-%s-x86_64.spk" % version, "browser_download_url": "http://127.0.0.1:%d/x.spk" % REL_PORT, "size": 1},
            {"name": name, "browser_download_url": "http://127.0.0.1:%d/%s" % (REL_PORT, name),
             "size": os.path.getsize(tgz), "digest": "sha256:" + digest}]}, f)


class _Quiet(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *a, **k):
        super().__init__(*a, directory=REL_DIR, **k)

    def log_message(self, *a):
        pass


_REL_SERVER = []


def _serve_releases():
    os.makedirs(REL_DIR, exist_ok=True)
    if _REL_SERVER:
        return
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", REL_PORT), _Quiet)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    _REL_SERVER.append(srv)


UPD_ENV = dict(ENV, BARRIER_UPDATE_DIR=UPD_DIR, BARRIER_RELEASE_URL="http://127.0.0.1:%d/latest.json" % REL_PORT)


def _with_update_server():
    SRV.stop()
    SRV.env = UPD_ENV
    SRV.start()


@test
def update_check_sees_newer_version():
    _serve_releases()
    release("9.9.9")
    _with_update_server()
    u = call("/api/update/check", "POST")[1]
    check(u["available"] and u["latest"] == "9.9.9" and u["can_install"], "should see 9.9.9 as installable: %s" % u)
    check(u["auto_update"] is True, "automatic updates should be on by default")


@test
def update_refuses_tampered_download():
    release("9.9.9", tamper=True)
    call("/api/update/check", "POST")
    call("/api/update/install", "POST")
    for _ in range(40):
        u = call("/api/update")[1]
        if u["progress"] and u["progress"]["phase"] == "failed":
            break
        time.sleep(0.25)
    check(u["progress"]["phase"] == "failed" and "checksum" in u["progress"]["message"], "a bad checksum must stop it: %s" % u)
    check(not os.path.exists(os.path.join(UPD_DIR, "next")), "nothing may be staged")
    check(SRV.proc.poll() is None, "Barrier must keep running")
    check(u["last_result"] and not u["last_result"]["ok"], "the failure should be remembered")


@test
def update_installs_then_reconnects():
    call("/api/settings", "POST", {"auto_connect": False})
    call("/api/connect", "POST", {"key": "usa_-_new_york"})
    wait_state({"connected"})
    release("9.9.9")
    call("/api/update/check", "POST")
    code0, r = call("/api/update/install", "POST")
    check(code0 == 200 and r["installing"], "should start installing: %s" % r)
    try:
        code = SRV.proc.wait(timeout=20)
    except subprocess.TimeoutExpired:
        raise AssertionError("Barrier should exit to swap in the update")
    SRV.proc = None
    check(code == 75, "should exit with 75 (restart into the update), got %s" % code)
    with open(os.path.join(UPD_DIR, "next", "VERSION")) as f:
        check(f.read().strip() == "9.9.9", "the new version should be staged in next/")
    check(os.path.exists(os.path.join(CFG, "reconnect-after-update")), "it should remember to reconnect")
    # The start script would swap next/ in; starting again is enough to test the reconnect.
    SRV.start()
    st = wait_state({"connected"}, timeout=15)
    check(st["state"] == "connected", "should reconnect after the update even with auto-connect off: %s" % st)
    check(not os.path.exists(os.path.join(CFG, "reconnect-after-update")), "the reminder should be cleared")
    u = call("/api/update")[1]
    check(u["last_result"]["ok"] and u["last_result"]["to"] == "9.9.9", "should record the update: %s" % u["last_result"])
    call("/api/disconnect", "POST", {})


@test
def update_unavailable_without_package():
    SRV.stop()
    SRV.env = ENV
    SRV.start()
    release("9.9.9")
    u = call("/api/update")[1]
    check(not u["can_install"], "without the package script it can't update itself")
    code, j = call("/api/update/install", "POST")
    check(code == 400 and "package" in j.get("error", ""), "install should be refused: %s %s" % (code, j))

@test
def page_script_is_valid():
    """The whole page breaks if its script has one syntax error (1.1.2–1.1.6: an apostrophe)."""
    node = shutil.which("node")
    if not node:
        raise RuntimeError("node is needed to check the page's script")
    import re
    html = open(os.path.join(APP_DIR, "static", "index.html")).read()
    js = os.path.join(TMP, "page.js")
    open(js, "w").write("\n".join(re.findall(r"<script>(.*?)</script>", html, re.S)))
    r = subprocess.run([node, "--check", js], capture_output=True, text=True)
    check(r.returncode == 0, r.stderr.strip()[:400])


@test
def page_buttons_work_in_a_browser():
    """Opens the real page in Chrome and uses it like a person would."""
    from playwright.sync_api import sync_playwright
    chrome = shutil.which("google-chrome") or shutil.which("chromium") or shutil.which("chromium-browser")
    if not chrome:
        raise RuntimeError("Chrome is needed for the browser test")
    _serve_releases()
    release("9.9.9")
    _with_update_server()
    call("/api/credentials", "POST", {"username": "u", "password": "p"})
    os.makedirs(os.path.join(CFG, "configs"), exist_ok=True)
    open(os.path.join(CFG, "configs", "my_expressvpn_usa_-_new_york_udp.ovpn"), "w").write(ovpn())
    call("/api/settings", "POST", {"auto_update": False, "kill_switch": True})
    call("/api/disconnect", "POST", {})
    call("/api/connect", "POST", {"key": "usa_-_new_york"})   # remembers it as the last location
    wait_state({"connected"})
    call("/api/disconnect", "POST", {})
    wait_state({"disconnected"})
    errors = []
    with sync_playwright() as pw:
        browser = pw.chromium.launch(executable_path=chrome, args=["--no-sandbox"])
        page = browser.new_context(http_credentials={"username": "me", "password": PW}).new_page()
        page.on("pageerror", lambda e: errors.append(str(e)))
        page.on("dialog", lambda d: d.accept())
        page.goto("http://127.0.0.1:%d/" % PORT)
        T = 20000

        # The page's script runs: status and version fill in.
        page.wait_for_function("document.getElementById('stateText').textContent === 'Not connected'", timeout=T)
        page.wait_for_function("!document.getElementById('updState').textContent.includes('–')", timeout=T)
        check(not errors, "script errors on load: %s" % errors)

        # Connect, then Disconnect, with the big button.
        page.click("#power")
        page.wait_for_function("document.getElementById('stateText').textContent === 'Connected'", timeout=T)
        check(page.text_content("#powerLabel") == "Disconnect")
        page.click("#power")
        page.wait_for_function("document.getElementById('stateText').textContent === 'Not connected'", timeout=T)

        # Check now finds the newer version and shows Update now.
        page.click("#updCheck")
        page.wait_for_function("document.getElementById('updState').textContent.includes('9.9.9 is available')", timeout=T)
        check(page.is_visible("#updNow"), "Update now should appear")

        # Check setup runs and reports.
        page.click("#testBtn")
        page.wait_for_function("document.getElementById('testRes').children.length > 0 && document.getElementById('testSum').textContent.length > 0", timeout=60000)

        # Kill switch test: while disconnected it says to connect first.
        page.click("#deepBtn")
        page.wait_for_function("/connect/i.test(document.getElementById('testStep').textContent)", timeout=T)

        # Connected: it actually runs, shows its steps, and finishes with results.
        page.click("#power")
        page.wait_for_function("document.getElementById('stateText').textContent === 'Connected'", timeout=T)
        page.click("#deepBtn")
        page.wait_for_function("document.getElementById('testStep').textContent.length > 0 && document.getElementById('deepBtn').disabled", timeout=T)
        page.wait_for_function("!document.getElementById('deepBtn').disabled && document.getElementById('testSum').textContent.length > 0", timeout=150000)
        names = page.text_content("#testRes")
        check("kill switch" in names.lower() or "VPN is down" in names, "kill switch results should show: %s" % names[:300])

        # Update now downloads it, shows its progress, and Barrier exits to swap it in.
        page.click("#updNow")
        page.wait_for_function("document.getElementById('updBarWrap').style.display === ''", timeout=T)
        try:
            code = SRV.proc.wait(timeout=60)
        except subprocess.TimeoutExpired:
            raise AssertionError("Update now should make Barrier restart into the update")
        SRV.proc = None
        check(code == 75, "should exit with 75 to swap in the update, got %s" % code)
        # (On the NAS the start script swaps it in here.) The page picks Barrier up again.
        SRV.start()
        page.wait_for_function("['Connected','Reconnecting…','Connecting…'].includes(document.getElementById('stateText').textContent)", timeout=T)
        check(not errors, "script errors while using the page: %s" % errors)
        browser.close()
    call("/api/disconnect", "POST", {})


# ================================================================ runner
SRV = Server()


def main():
    only = sys.argv[1] if len(sys.argv) > 1 else ""
    SRV.start()
    passed = failed = 0
    try:
        for fn in RESULTS:
            if only and only not in fn.__name__:
                continue
            t0 = time.time()
            try:
                fn()
                print("  PASS  %-42s %.1fs" % (fn.__name__, time.time() - t0))
                passed += 1
            except Exception as e:
                print("  FAIL  %-42s %s" % (fn.__name__, e))
                if os.environ.get("VERBOSE"):
                    traceback.print_exc()
                failed += 1
    finally:
        SRV.stop()
        shutil.rmtree(TMP, ignore_errors=True)
    print("\n%d passed, %d failed" % (passed, failed))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
