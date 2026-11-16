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
mkdir -p "$CONF" "$UPD"

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
if [ ! -e "$CONF/settings.json" ]; then
	for OLD in "$OLDROOT/barrier" "$OLDROOT/nas-vpn"; do
		if [ -e "$OLD/config/settings.json" ]; then
			echo "Bringing over settings from the old project ($OLD)"
			cp -a "$OLD/config/." "$CONF/"
			PW=$(sed -n 's/^[[:space:]]*-[[:space:]]*UI_PASSWORD=//p' "$OLD/docker-compose.yml" 2>/dev/null | head -n1 | tr -d '\r' | sed "s/^[\"']//; s/[\"']$//")
			if [ -n "$PW" ] && [ ! -e "$CONF/page-password" ]; then
				(umask 077; printf '%s' "$PW" > "$CONF/page-password")
				echo "Page password carried over"
			fi
			break
		fi
	done
fi

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
