#!/bin/sh
# Runs after OpenVPN has set up its routes. Points the container's DNS at the VPN's DNS
# servers so lookups go through the tunnel instead of leaking to your ISP.
TMP=/tmp/barrier-resolv.vpn
: > "$TMP"
i=1
while :; do
  eval "opt=\$foreign_option_$i"
  [ -z "$opt" ] && break
  case "$opt" in
    "dhcp-option DNS "*)
      ns="${opt#dhcp-option DNS }"
      echo "nameserver $ns" >> "$TMP"
      # make sure the DNS server is reached through the tunnel even if it sits inside a LAN-looking range
      ip route add "$ns/32" dev "$dev" 2>/dev/null
      ;;
  esac
  i=$((i + 1))
done
if [ ! -s "$TMP" ]; then
  echo "nameserver ${NASVPN_DNS_FALLBACK:-1.1.1.1}" > "$TMP"
fi
[ -f /tmp/barrier-resolv.orig ] || cat /etc/resolv.conf > /tmp/barrier-resolv.orig
cat "$TMP" > /etc/resolv.conf
exit 0
