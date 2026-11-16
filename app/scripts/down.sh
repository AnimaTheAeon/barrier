#!/bin/sh
# Runs when the VPN goes down: put the container's original DNS settings back.
if [ -f /tmp/barrier-resolv.orig ]; then
  cat /tmp/barrier-resolv.orig > /etc/resolv.conf
fi
exit 0
