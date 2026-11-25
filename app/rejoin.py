"""Keeps Lifestream attached to this Barrier.

Lifestream shares Barrier's network (network_mode "container:barrier"), but
Docker pins that to the Barrier container that existed when Lifestream was
created. When the Barrier package is installed or upgraded, its container is
replaced, and Lifestream is left in an empty network with no internet; even
restarting it fails. Here Barrier spots that and creates Lifestream again with
the same settings, joined to the current Barrier.

Needs the Docker socket (mounted by the package). Without it this does nothing.
"""
import http.client
import json
import os
import socket
import urllib.parse

SOCK = os.environ.get("DOCKER_SOCK", "/var/run/docker.sock")
ME = os.environ.get("BARRIER_CONTAINER", "barrier")
TARGET = os.environ.get("LIFESTREAM_CONTAINER", "lifestream")

# Docker refuses these together with another container's network.
_NET_CONFIG = ("Hostname", "Domainname", "ExposedPorts", "MacAddress")
_NET_HOST = ("PortBindings", "PublishAllPorts", "Dns", "DnsOptions", "DnsSearch", "ExtraHosts", "Links")


class _Conn(http.client.HTTPConnection):
    def __init__(self, path, timeout=30):
        super().__init__("localhost", timeout=timeout)
        self._path = path

    def connect(self):
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(self.timeout)
        s.connect(self._path)
        self.sock = s


def _call(method, path, body=None, timeout=30):
    conn = _Conn(SOCK, timeout)
    try:
        data = json.dumps(body).encode() if body is not None else None
        conn.request(method, path, body=data, headers={"Content-Type": "application/json"} if data else {})
        r = conn.getresponse()
        raw = r.read()
        try:
            out = json.loads(raw) if raw else None
        except ValueError:
            out = raw.decode(errors="replace")
        return r.status, out
    finally:
        conn.close()


def available():
    return os.path.exists(SOCK)


def recreate_spec(info, net_target):
    """Body for POST /containers/create: the same container, on `net_target`'s network."""
    cfg = dict(info["Config"])
    for k in _NET_CONFIG:
        cfg.pop(k, None)
    host = dict(info["HostConfig"])
    for k in _NET_HOST:
        host.pop(k, None)
    host["NetworkMode"] = "container:" + net_target
    cfg["HostConfig"] = host
    return cfg


def should_start(info):
    """Start the new copy if the old one was running, or died only because Barrier went away."""
    st = info.get("State", {})
    if st.get("Running"):
        return True
    return "network namespace" in (st.get("Error") or "")


def needs_restart(info, me):
    """Lifestream is running (or died trying) but started before Barrier's container last started."""
    st = info.get("State", {})
    if not st.get("Running") and "network namespace" not in (st.get("Error") or ""):
        return False  # stopped on purpose: leave it
    mine, theirs = _when(me.get("State", {}).get("StartedAt")), _when(st.get("StartedAt"))
    return mine is not None and theirs is not None and theirs < mine


def _when(stamp):
    """Docker's RFC 3339 time (nanoseconds, trailing zeros dropped) as (seconds, nanoseconds)."""
    import re
    from datetime import datetime, timezone
    m = re.match(r"(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(?:\.(\d+))?Z?$", stamp or "")
    if not m or m.group(1).startswith("0001"):
        return None
    base = int(datetime.strptime(m.group(1), "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc).timestamp())
    return (base, int((m.group(2) or "0").ljust(9, "0")[:9]))


def check(log=print):
    """Returns what happened: 'no-docker', 'no-lifestream', 'ok', 'rejoined', 'restarted' or 'error: ...'."""
    if not available():
        return "no-docker"
    try:
        code, me = _call("GET", "/containers/%s/json" % ME)
        if code != 200:
            return "error: can't see Barrier's own container (%s)" % code
        code, info = _call("GET", "/containers/%s/json" % TARGET)
        if code == 404:
            return "no-lifestream"
        if code != 200:
            return "error: can't look at Lifestream (%s)" % code
        mode = info["HostConfig"].get("NetworkMode", "")
        if not mode.startswith("container:"):
            return "ok"  # not using Barrier's network; leave it alone
        if mode[len("container:"):] in (me["Id"], ME):
            if needs_restart(info, me):
                # Barrier's container restarted after Lifestream started: Lifestream still sits
                # in the old, empty network. A restart puts it into this one.
                log("Barrier restarted after Lifestream; restarting Lifestream so it joins the new network")
                code, out = _call("POST", "/containers/%s/restart?t=20" % TARGET, timeout=60)
                if code not in (204, 304):
                    return "error: couldn't restart Lifestream (%s %s)" % (code, out)
                return "restarted"
            return "ok"
        start = should_start(info)
        spec = recreate_spec(info, me["Id"])
        log("Lifestream is attached to an old Barrier; reconnecting it")
        if info.get("State", {}).get("Running"):
            _call("POST", "/containers/%s/stop?t=20" % TARGET, timeout=40)
        code, out = _call("DELETE", "/containers/%s" % TARGET)
        if code not in (204, 404):
            return "error: couldn't remove the old Lifestream (%s %s)" % (code, out)
        code, out = _call("POST", "/containers/create?name=" + urllib.parse.quote(TARGET), spec)
        if code != 201:
            return "error: couldn't create Lifestream again (%s %s)" % (code, out)
        if start:
            code, out = _call("POST", "/containers/%s/start" % TARGET)
            if code not in (204, 304):
                return "error: couldn't start Lifestream (%s %s)" % (code, out)
        log("Lifestream reconnected to this Barrier" + ("" if start else " (left stopped, as it was)"))
        return "rejoined"
    except (OSError, KeyError, ValueError, http.client.HTTPException) as e:
        return "error: %s" % e
