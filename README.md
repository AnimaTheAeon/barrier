# Barrier: ExpressVPN on your Synology

Barrier runs your ExpressVPN on a Synology NAS and gives you a web page to connect, disconnect and pick locations. It uses ExpressVPN's **manual OpenVPN** files, which ExpressVPN supports for third-party devices.

What you get: a location list with search, UDP/TCP switch, connect/disconnect, live IP and speed, a kill switch, auto-reconnect, auto-connect after a reboot, a self-test, and updates from inside the app.

Other apps can send their traffic through it. [Lifestream](https://github.com/AnimaTheAeon/Lifestream) lives inside Barrier's network, so its traffic can only leave through the VPN. Barrier does **not** send the NAS's own traffic (DSM, Plex and so on) through the VPN.

---

## Install

1. Download the newest `Barrier-<version>-x86_64.spk` from [Releases](https://github.com/AnimaTheAeon/Barrier/releases).
2. **Package Center → Manual Install** → pick the file → Next. Container Manager is installed first if you don't have it.
3. Open **Barrier** from the DSM main menu, or `http://<your-NAS>:8085`.

The package carries everything it needs, so the NAS doesn't build or download anything to install it. No Task Scheduler task is needed either: Barrier switches on the VPN's tunnel device by itself when it starts.

### Moving from the old Container Manager project

If you set up Barrier (or "NAS VPN") by hand before, in `docker/barrier` or `docker/nas-vpn`:

1. **Container Manager → Project →** select the old project → **Action → Stop**, then **Action → Delete**. Keep its files.
2. Install the package as above. On its first start Barrier brings over your ExpressVPN login, locations, settings and page password from the old folder.
3. Install the **Lifestream** .spk again (**Package Center → Manual Install**; the same version is fine) so it joins the new Barrier. Stopping and starting Lifestream isn't enough: it stays tied to the old Barrier container.
4. Optional: delete the old "Enable TUN" boot task in Task Scheduler, and the old project folder once everything works.

## Set it up

1. Sign in at expressvpn.com → **Set up on more devices** → **Manual Config** → **OpenVPN**. Copy the **username** and **password** shown there (these are *not* your email and login password), and download the location files (.ovpn) you want.
2. In Barrier: **ExpressVPN account** → paste the username and password → Save.
3. **Add locations**: drop the .ovpn files (or a .zip of them) onto the box.
4. Pick a location and press **Connect**. The ring turns green and the public IP changes.
5. Optional: in **Settings**, turn on **Connect automatically** so it comes back after a reboot, and set a **page password**.

## Updates

The **Updates** card shows the installed and newest versions.

- **Update now** downloads the new version from GitHub, checks it against GitHub's checksum and restarts Barrier on it.
- **Install updates automatically** (on by default) checks every 6 hours and does the same by itself.

Only Barrier's own app restarts, for a few seconds. The container keeps running, so Lifestream inside it isn't interrupted. The kill switch stays on the whole time, and Barrier reconnects to the same location afterwards. If a new version won't start, Barrier goes back to the one that came with the package.

A new **package** (the .spk) is only needed when the container itself changes. Installing one replaces Barrier's container, so afterwards install the Lifestream .spk again (Manual Install, same version is fine) to join the new one.

## Checking that it really works (Self-test)

At the bottom of the page there's a **Self-test** card.

- **Check setup**: safe to press any time. It checks the tunnel device, permissions, firewall, your login, your location files and DNS. While connected, it also checks that:
  - your IP really changed,
  - traffic can't go around the VPN,
  - DNS goes through the VPN,
  - IPv6 isn't leaking.
- **Test kill switch**: connect first. It cuts the VPN on purpose, checks that no traffic escapes, then checks that the VPN reconnects by itself. Apps inside Barrier lose internet for about 30 seconds.

Every problem comes with a plain "What to do" line. **Copy report** puts the whole result on your clipboard.

## Sending another app through the VPN

Any container can join Barrier's network with `network_mode: "container:barrier"`. Its web page then has to be published by Barrier, so it needs a port added to Barrier's package; open an issue for that. Lifestream's port 9091 is already published.

With the kill switch on, an app inside Barrier has no internet while the VPN is down, and nothing leaks.

## If something goes wrong

| What you see | What to do |
|---|---|
| Self-test: "TUN device" is red | Stop and run Barrier in Package Center. If it stays red, open **Container Manager → Container → barrier → Log** and look for the lines starting with `TUN:`. |
| "Login rejected" | Re-copy the username and password from the Manual Config page (not your email login). |
| Stuck on "Connecting…" | Open **Connection log** on the page. Try the TCP switch, or another location. |
| "Kill switch unavailable" banner | Your NAS blocks firewall changes inside containers. The VPN still works, but traffic isn't blocked if it drops. |
| Can't reach the page after connecting | Your home network isn't in **Home network ranges** (Settings). Add it, e.g. `192.168.5.0/24`. |
| Lifestream won't start | Barrier must be running first. If Barrier's container was replaced (a Barrier .spk install, or the project re-created), install the Lifestream .spk again. |

Your login, locations and settings live in `/var/packages/Barrier/var` and are kept when Barrier updates. Keep the page on your home network and never forward port 8085 on your router.

## For developers

- `python3 tests/run_tests.py` runs the app's automated tests against a fake OpenVPN (needs Flask). They prove the app's logic, not your NAS; the Self-test checks your NAS.
- `synology/build-spk.sh` builds the .spk and the app download that updates use. It needs Docker.
- Pushing a new `VERSION` to `main` publishes a release; its notes come from that version's section in `CHANGES.md`.
