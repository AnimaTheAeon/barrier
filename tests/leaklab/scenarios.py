"""Leak scenarios. Each returns a result dict; 'leaks' and 'dns_leaks' must be empty."""
import json
import threading
import time

import lab

RESULTS = {}


class Prober:
    """Keeps trying to reach the fake internet directly from inside Barrier's network,
    as Lifestream's user (1026) - a stand-in for any program in there that isn't bound to the tunnel."""

    def __init__(self, uid="1026", seconds=30):
        self.uid, self.seconds, self.result = uid, seconds, None
        self.t = threading.Thread(target=self._run, daemon=True)

    def _run(self):
        self.result = lab.probe(self.uid, self.seconds)

    def start(self):
        self.t.start()
        return self

    def join(self):
        self.t.join()
        return self.result


def snapshot():
    try:
        st = lab.ls_state()
        return {"killHold": st.get("killHold"), "adapterIp": st.get("adapterIp"), "reason": st.get("killReason")}
    except Exception as e:
        return {"lifestream": "unreachable: %s" % type(e).__name__}


def judge(name, m, extra=None, expect_vpn_after=False):
    ev = lab.events_since(m)
    bad, dns = lab.leaks(ev)
    r = {"leaks": [(e["kind"], e.get("proto", ""), e.get("port", ""), e["src"]) for e in bad][:8],
         "leak_count": len(bad), "dns_leaks": sorted(set(e["q"] for e in dns))[:8],
         "through_vpn": len(lab.through_vpn(ev))}
    if extra:
        r.update(extra)
    if expect_vpn_after:
        r["recovered"] = r["through_vpn"] > 0
    r["PASS"] = not bad and not dns and (r.get("recovered", True) is True) and r.get("ok", True)
    RESULTS[name] = r
    print(name, json.dumps(r))
    return r


def ensure_connected(timeout=90):
    if lab.barrier_state() != "connected":
        lab.bapi("/api/connect", "POST", {"last": True})
    return lab.wait_barrier({"connected"}, timeout)


def reannounce():
    try:
        ids = [t["id"] for t in lab.rpc("torrent-get", {"fields": ["id"]})["arguments"]["torrents"]]
        lab.rpc("torrent-reannounce", {"ids": ids})
    except Exception:
        pass


def wait_traffic(m, timeout=60):
    end = time.time() + timeout
    while time.time() < end:
        if lab.through_vpn(lab.events_since(m)):
            return True
        reannounce()
        time.sleep(5)
    return False


# ------------------------------------------------------------------ scenarios
def vpn_server_dies():
    ensure_connected()
    m = lab.mark()
    p = Prober(seconds=70).start()
    lab.sh("docker stop -t 0 vpnserver")
    time.sleep(70)
    held = snapshot()
    p.join()
    lab.sh("docker start vpnserver")
    ensure_connected(120)
    m2 = lab.mark()
    back = wait_traffic(m2, 90)
    return judge("vpn_server_dies", m, {"while_down": held, "probe": p.result, "ok": back})


def user_disconnects():
    ensure_connected()
    m = lab.mark()
    lab.bapi("/api/disconnect", "POST", {})
    time.sleep(3)
    p = Prober(seconds=25).start()
    for _ in range(4):
        reannounce()
        time.sleep(6)
    held = snapshot()
    p.join()
    r = judge("user_disconnects", m, {"while_down": held, "probe": p.result, "ok": held.get("killHold") is True})
    ensure_connected()
    return r


def barrier_kill_switch_off():
    ensure_connected()
    before = lab.bapi("/api/settings", "POST", {"kill_switch": False})
    m = lab.mark()
    lab.bapi("/api/disconnect", "POST", {})
    time.sleep(3)
    p = Prober(seconds=25).start()
    for _ in range(4):
        reannounce()
        time.sleep(6)
    held = snapshot()
    p.join()
    after = lab.bapi("/api/settings")
    r = judge("barrier_kill_switch_off", m, {"setting_change": before.get("kill_switch", before), "kill_switch_now": after.get("kill_switch"),
                                             "while_down": held, "probe": p.result})
    lab.bapi("/api/settings", "POST", {"kill_switch": True})
    ensure_connected()
    return r


def lifestream_kill_switch_off():
    ensure_connected()
    ch = lab.ls_settings({"kill_switch": False})
    m = lab.mark()
    lab.bapi("/api/disconnect", "POST", {})
    time.sleep(3)
    for _ in range(4):
        reannounce()
        time.sleep(6)
    held = snapshot()
    now = lab.ls_settings().get("kill_switch")
    r = judge("lifestream_kill_switch_off", m, {"lifestream_kill_switch_now": now, "while_down": held})
    lab.ls_settings({"kill_switch": True})
    ensure_connected()
    return r


def both_kill_switches_off():
    ensure_connected()
    lab.bapi("/api/settings", "POST", {"kill_switch": False})
    lab.ls_settings({"kill_switch": False})
    m = lab.mark()
    lab.bapi("/api/disconnect", "POST", {})
    time.sleep(3)
    for _ in range(5):
        reannounce()
        time.sleep(6)
    held = snapshot()
    r = judge("both_kill_switches_off", m, {"barrier_ks": lab.bapi("/api/settings").get("kill_switch"),
                                            "lifestream_ks": lab.ls_settings().get("kill_switch"), "while_down": held})
    lab.ls_settings({"kill_switch": True})
    lab.bapi("/api/settings", "POST", {"kill_switch": True})
    ensure_connected()
    return r


def barrier_app_restarts():
    ensure_connected()
    m = lab.mark()
    p = Prober(seconds=30).start()
    time.sleep(1)
    lab.sh("docker exec barrier pkill -f /opt/barrier/app/app.py", check=False)
    lab.sh("docker exec barrier pkill -f /config/app-update/current/app.py", check=False)
    time.sleep(30)
    p.join()
    ok = ensure_connected(90) == "connected"
    m2 = lab.mark()
    back = wait_traffic(m2, 90)
    return judge("barrier_app_restarts", m, {"probe": p.result, "ok": ok and back})


def barrier_container_restarts():
    ensure_connected()
    m = lab.mark()
    lab.sh("docker restart -t 5 barrier")
    p = Prober(seconds=25).start()
    p.join()
    ensure_connected(120)
    time.sleep(15)
    m2 = lab.mark()
    back = wait_traffic(m2, 90)
    return judge("barrier_container_restarts", m, {"probe": p.result, "lifestream_after": snapshot(), "ok": back})


def barrier_container_replaced():
    ensure_connected()
    m = lab.mark()
    lab.sh("docker rm -f barrier")
    lab.run_barrier(lab.images()["barrier"])
    p = Prober(seconds=25).start()
    p.join()
    ensure_connected(120)
    time.sleep(15)
    m2 = lab.mark()
    back = wait_traffic(m2, 90)
    return judge("barrier_container_replaced", m, {"probe": p.result, "lifestream_after": snapshot(), "ok": back})


def cold_start_vpn_unavailable():
    """NAS boots, the VPN server can't be reached: nothing may get out."""
    lab.sh("docker stop -t 2 lifestream barrier")
    lab.sh("docker stop -t 0 vpnserver")
    m = lab.mark()
    lab.sh("docker start barrier")
    lab.sh("docker start lifestream", check=False)
    p = Prober(seconds=40).start()
    time.sleep(5)
    for _ in range(6):
        reannounce()
        time.sleep(5)
    held = snapshot()
    p.join()
    lab.sh("docker start vpnserver")
    ok = ensure_connected(150) == "connected"
    time.sleep(10)
    m2 = lab.mark()
    back = wait_traffic(m2, 90)
    return judge("cold_start_vpn_unavailable", m, {"probe": p.result, "while_down": held, "ok": ok and back})


def dns_while_down():
    ensure_connected()
    m = lab.mark()
    lab.bapi("/api/disconnect", "POST", {})
    time.sleep(3)
    out = lab.sh("docker exec -u 1026 barrier python -c \"import socket\nfor n in ('tracker.lab','leakcheck.lab'):\n  try: print(n, socket.gethostbyname(n))\n  except Exception as e: print(n, 'failed')\"", check=False)
    for _ in range(3):
        reannounce()
        time.sleep(5)
    r = judge("dns_while_down", m, {"lookup_as_lifestream_user": out.replace("\n", "; ")})
    ensure_connected()
    return r


def home_range_bypass():
    """Sneaking an internet range into 'home network ranges' must be refused."""
    ensure_connected()
    tries = {}
    for rng in (["0.0.0.0/0"], ["198.51.100.0/24"], ["128.0.0.0/1", "0.0.0.0/1"]):
        res = lab.bapi("/api/settings", "POST", {"lan_subnets": rng})
        tries[",".join(rng)] = res.get("_status") or ("unreachable" if "_error" in res else "accepted")
    now = lab.bapi("/api/settings").get("lan_subnets")
    m = lab.mark()
    lab.bapi("/api/disconnect", "POST", {})
    time.sleep(3)
    p = Prober(seconds=15).start()
    p.join()
    r = judge("home_range_bypass", m, {"attempts": tries, "lan_now": now, "probe": p.result,
                                        "ok": all(v == 400 for v in tries.values())})
    lab.bapi("/api/settings", "POST", {"lan_subnets": ["192.168.0.0/16", "172.16.0.0/12", "10.0.0.0/8"]})
    ensure_connected()
    return r


ALL = [vpn_server_dies, user_disconnects, barrier_kill_switch_off, lifestream_kill_switch_off,
       both_kill_switches_off, barrier_app_restarts, barrier_container_restarts,
       barrier_container_replaced, cold_start_vpn_unavailable, dns_while_down, home_range_bypass]


def main(args):
    names = args[0].split(",") if args and args[0] != "all" else [f.__name__ for f in ALL]
    for n in names:
        try:
            globals()[n]()
        except Exception as e:
            RESULTS[n] = {"PASS": False, "error": repr(e)[:300]}
            print(n, "ERROR", repr(e)[:300])
    print("\nSUMMARY")
    for n in names:
        print("  %s  %s" % ("PASS" if RESULTS.get(n, {}).get("PASS") else "FAIL", n))
    json.dump(RESULTS, open(lab.RUN + "/results.json", "w"), indent=1)
    return all(RESULTS.get(n, {}).get("PASS") for n in names)
