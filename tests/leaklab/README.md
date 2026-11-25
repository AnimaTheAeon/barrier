# Leak lab

Proves that nothing in Barrier's network (Lifestream included) reaches the internet except through the VPN.

It runs the real Barrier and Lifestream images, a real OpenVPN server, and a fake internet. The fake internet has a tracker, a peer, a web server and DNS, and it logs the source address of every contact. Anything that arrives from somewhere other than the VPN server counts as a leak. So does a torrent name looked up at the "router" DNS.

A prober also runs inside Barrier's network as Lifestream's user (uid 1026). It keeps trying to reach the fake internet directly, so the firewall is tested on its own and not only through Lifestream behaving well.

Needs a Linux machine with Docker, `/dev/net/tun`, iptables, openssl and Python 3. Run it as root. It changes the host firewall (DOCKER-USER, raw PREROUTING) so the host can play the home router. It is not run in CI.

```
python3 lab.py up [barrier-image] [lifestream-image]   # default: the released package images
python3 lab.py all                                       # every scenario; results in run/results.json
python3 lab.py vpn_server_dies,cold_start_vpn_unavailable
python3 lab.py down
```

To get the images, load them from the release packages: `tar xf X.spk package.tgz; tar xzf package.tgz image.tar.gz; docker load -i image.tar.gz`.

## Scenarios

- `vpn_server_dies`: the VPN server disappears while downloading. Nothing leaks, and traffic resumes through the VPN once the server is back.
- `user_disconnects`: Disconnect in Barrier. Nothing leaks, and Lifestream pauses.
- `barrier_kill_switch_off`: turning the kill switch off is refused.
- `lifestream_kill_switch_off`: turning Lifestream's kill switch off is refused.
- `both_kill_switches_off`: both of the above together.
- `barrier_app_restarts`: Barrier's app restarts, for example during an update.
- `barrier_container_restarts`: no leak while the container restarts, and Lifestream rejoins afterwards.
- `barrier_container_replaced`: a package install replaces the container. No leak, and Lifestream rejoins.
- `cold_start_vpn_unavailable`: a boot with the VPN unreachable. Nothing gets out.
- `dns_while_down`: Lifestream's name lookups can't go outside the tunnel.
- `home_range_bypass`: internet ranges can't be added as "home network".

## Results

Barrier 1.1.8 with Lifestream 1.3.26 (2026-11-25): 11 of 11 pass, with no leaks.

The same scenarios on 1.1.7 with 1.3.25 found these gaps:
- **VPN handshake port:** traffic to it was let out for any program to any address.
- **Startup:** there was a gap of a few seconds before the firewall came up.
- **Kill switches:** both could be turned off, and with both off Lifestream leaked.
- **Container restart:** Lifestream was left without a network after Barrier's container restarted.
- **Home ranges:** these accepted internet ranges, which also locked Barrier's own page out.
