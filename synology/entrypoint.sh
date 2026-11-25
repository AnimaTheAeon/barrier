#!/bin/sh
# Starts Barrier inside its container (the Barrier package runs it through
# Container Manager). It:
#   1. switches on the VPN tunnel device, so no DSM boot task is needed;
#   2. brings over settings from the old hand-made Container Manager project once;
#   3. runs the app, and swaps in updates the app downloads itself: the app
#      unpacks a new version into $UPD/next and exits with 75. An update that
#      stops within 30 seconds is put aside and the built-in version runs.
BUILT=${BARRIER_BUILT:-/opt/barrier/app}
CONF=${CONFIG_DIR:-/config}
OLDROOT=${BARRIER_OLD_DIR:-/old}
UPD=${BARRIER_UPDATE_DIR:-$CONF/app-update}
export BARRIER_UPDATE_DIR="$UPD"
echo "Running as $(id -un 2>/dev/null || id -u) (uid $(id -u))"
if [ "$(id -u)" != 0 ]; then
	echo "Barrier needs to run as root to build the VPN tunnel and the kill switch; it's running as uid $(id -u). Reinstall the Barrier package."
fi
mkdir -p "$CONF" "$UPD"

# 0. Kill switch first, before anything else runs: until Barrier's app takes over
#    (it swaps in its full rules in one step), only loopback, the tunnel, the LAN
#    and Barrier's own name lookups may leave. Lifestream shares this network and
#    may start any moment, so there must be no window without it.
lockdown() {
	for B in iptables-legacy iptables; do
		command -v "$B-restore" >/dev/null 2>&1 && "$B" -w -L -n >/dev/null 2>&1 || continue
		OWN="-m owner ! --uid-owner 0"
		"$B" -w -N BARRIER_OWNER_T 2>/dev/null
		"$B" -w -A BARRIER_OWNER_T -m owner --uid-owner 0 -j RETURN 2>/dev/null || OWN=""
		"$B" -w -F BARRIER_OWNER_T 2>/dev/null; "$B" -w -X BARRIER_OWNER_T 2>/dev/null
		{
			echo "*filter"
			echo ":NASVPN_KS - [0:0]"
			[ -n "$OWN" ] && echo "-A NASVPN_KS -o lo -d 127.0.0.11 $OWN -j DROP"
			echo "-A NASVPN_KS -o lo -j ACCEPT"
			echo "-A NASVPN_KS -o tun+ -j ACCEPT"
			[ -n "$OWN" ] && echo "-A NASVPN_KS -p udp --dport 53 $OWN -j DROP" && echo "-A NASVPN_KS -p tcp --dport 53 $OWN -j DROP"
			for N in 192.168.0.0/16 172.16.0.0/12 10.0.0.0/8; do echo "-A NASVPN_KS -d $N -j ACCEPT"; done
			[ -n "$OWN" ] && echo "-A NASVPN_KS -p udp --dport 53 -m owner --uid-owner 0 -j ACCEPT" && echo "-A NASVPN_KS -p tcp --dport 53 -m owner --uid-owner 0 -j ACCEPT"
			echo "-A NASVPN_KS -j DROP"
			echo "COMMIT"
		} | "$B-restore" -w --noflush || continue
		"$B" -w -C OUTPUT -j NASVPN_KS 2>/dev/null || "$B" -w -I OUTPUT 1 -j NASVPN_KS
		B6=$(echo "$B" | sed 's/^iptables/ip6tables/')
		if command -v "$B6-restore" >/dev/null 2>&1; then
			printf '*filter\n:NASVPN_KS - [0:0]\n-A NASVPN_KS -o lo -j ACCEPT\n-A NASVPN_KS -o tun+ -j ACCEPT\n-A NASVPN_KS -j DROP\nCOMMIT\n' | "$B6-restore" -w --noflush 2>/dev/null \
				&& { "$B6" -w -C OUTPUT -j NASVPN_KS 2>/dev/null || "$B6" -w -I OUTPUT 1 -j NASVPN_KS; }
		fi
		echo "Kill switch: on from the start ($B)"
		return 0
	done
	echo "Kill switch: couldn't set up the firewall"
	return 1
}
if [ "${KILL_SWITCH_ALWAYS:-}" = 1 ] || grep -q '"kill_switch": *true' "$CONF/settings.json" 2>/dev/null; then
	lockdown
fi

# 1. The tunnel device. Synology doesn't load its tun module until something
#    asks; the package lets this container load it (SYS_MODULE, /lib/modules).
if [ -z "${BARRIER_SKIP_TUN:-}" ] && [ ! -c /dev/net/tun ]; then
	if ! grep -q '^tun ' /proc/modules 2>/dev/null && [ -f /lib/modules/tun.ko ]; then
		insmod /lib/modules/tun.ko 2>&1 | sed 's/^/TUN: /'
	fi
	mkdir -p /dev/net
	mknod /dev/net/tun c 10 200 2>/dev/null
	chmod 600 /dev/net/tun 2>/dev/null
fi
if [ -c /dev/net/tun ] && (exec 3<>/dev/net/tun) 2>/dev/null; then
	echo "TUN: ready"
else
	echo "TUN: not available. The VPN can't connect until it is; Barrier's Self-test says what to do."
fi

# 2. Settings from the earlier project (/volume1/docker/barrier, or nas-vpn
#    before the rename): login, locations and settings, plus the page password.
for OLD in "$OLDROOT/barrier" "$OLDROOT/nas-vpn"; do
	[ -e "$OLD/config/settings.json" ] || continue
	# Once: bring over the login, locations and settings. A first try that died
	# half-way (empty or missing files) is finished here; after it's complete
	# it never runs again, so locations removed later stay removed.
	if [ ! -e "$CONF/.migrated" ]; then
		[ -e "$CONF/auth.txt" ] && [ ! -s "$CONF/auth.txt" ] && rm -f "$CONF/auth.txt"
		for f in "$CONF"/configs/*.ovpn; do [ -e "$f" ] && [ ! -s "$f" ] && rm -f "$f"; done
		have_loc() { for f in "$CONF"/configs/*.ovpn; do [ -s "$f" ] && return 0; done; return 1; }
		if [ ! -s "$CONF/settings.json" ] || [ ! -s "$CONF/auth.txt" ] || ! have_loc; then
			echo "Bringing over settings from the old project ($OLD)"
			cp -Rn "$OLD/config/." "$CONF/"
			# The settings here came from the failed try (or don't exist): use the old
			# ones, so it reconnects to the same location by itself.
			cp -f "$OLD/config/settings.json" "$CONF/settings.json"
			chmod 600 "$CONF/auth.txt" 2>/dev/null
		fi
		if [ -s "$CONF/auth.txt" ] && have_loc; then
			touch "$CONF/.migrated"
			echo "Old settings in place: $(ls "$CONF"/configs/*.ovpn | wc -l) locations, login saved"
		else
			echo "Couldn't bring over the old login or locations from $OLD"
		fi
	fi
	# The page password, once. Kept apart so a first try that failed half-way
	# still brings it over, and a password removed later stays removed.
	if [ ! -e "$CONF/.page-password-migrated" ]; then
		PW=$(sed -n 's/^[[:space:]]*-[[:space:]]*UI_PASSWORD=//p' "$OLD/docker-compose.yml" 2>/dev/null | head -n1 | tr -d '\r' | sed "s/^[\"']//; s/[\"']$//")
		if [ -n "$PW" ] && [ ! -e "$CONF/page-password" ]; then
			(umask 077; printf '%s' "$PW" > "$CONF/page-password") && echo "Page password carried over"
		fi
		[ -e "$CONF/page-password" ] || [ -z "$PW" ] && touch "$CONF/.page-password-migrated"
	fi
	break
done

version() { cat "$1/VERSION" 2>/dev/null || echo 0; }
# True when version $1 is newer than version $2.
newer() { [ "$1" != "$2" ] && [ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | tail -n1)" = "$1" ]; }

pick() {
	rm -rf "$UPD/work"
	if [ -f "$UPD/next/app.py" ]; then
		rm -rf "$UPD/previous"
		[ -d "$UPD/current" ] && mv "$UPD/current" "$UPD/previous"
		mv "$UPD/next" "$UPD/current"
		chmod 755 "$UPD/current/scripts/"*.sh 2>/dev/null
	fi
	rm -rf "$UPD/next"
	if [ -f "$UPD/current/app.py" ] && newer "$(version "$UPD/current")" "$(version "$BUILT")"; then
		DIR="$UPD/current"
	else
		DIR="$BUILT"
	fi
}

STOPPING=0
PID=
stop() {
	STOPPING=1
	[ -n "$PID" ] && kill -TERM "$PID" 2>/dev/null
}
trap stop TERM INT

while :; do
	pick
	pkill -x openvpn 2>/dev/null
	echo "Starting Barrier $(version "$DIR")"
	STARTED=$(date +%s)
	${BARRIER_PYTHON:-python} -u "$DIR/app.py" &
	PID=$!
	wait "$PID"
	RC=$?
	if [ "$STOPPING" = 1 ]; then
		wait "$PID" 2>/dev/null
		exit 0
	fi
	[ "$RC" = 75 ] && continue
	if [ "$DIR" != "$BUILT" ] && [ $(( $(date +%s) - STARTED )) -lt 30 ]; then
		echo "The update stopped within 30 s (exit $RC); going back to the built-in version"
		rm -rf "$UPD/failed"
		mv "$UPD/current" "$UPD/failed"
		continue
	fi
	echo "Barrier stopped (exit $RC); starting it again"
	sleep 3
done
