#!/bin/sh
# Stand-in for OpenVPN used by run_tests.py. Behaviour is chosen by marker lines in the config.
[ "$1" = "--version" ] && { echo "OpenVPN mock 2.6.0"; exit 0; }
cfg=""; while [ $# -gt 0 ]; do [ "$1" = "--config" ] && cfg="$2"; shift; done
echo "2026-01-01 00:00:00 OpenVPN mock starting"
echo "$cfg" >> "${MOCK_LAUNCH_LOG:-/dev/null}"
if grep -q "^verb 3 BADAUTH" "$cfg"; then echo "AUTH: Received control message: AUTH_FAILED"; exit 1; fi
if grep -q "^verb 3 CRASH" "$cfg"; then echo "Connection reset, restarting"; exit 1; fi
sleep 1
echo "2026-01-01 00:00:01 Initialization Sequence Completed"
trap 'exit 0' TERM
while true; do sleep 1 & wait $!; done
