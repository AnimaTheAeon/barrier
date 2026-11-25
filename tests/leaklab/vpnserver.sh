#!/bin/sh
# Test VPN server for the leak lab: real OpenVPN, any login accepted, NAT out to the "internet".
iptables-legacy -t nat -A POSTROUTING -s 10.8.0.0/24 -o eth0 -j MASQUERADE 2>/dev/null \
  || iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o eth0 -j MASQUERADE
# DNS inside the tunnel: every name points at the test internet host.
python /lab/netsvc.py dns /log/events.jsonl vpn 198.51.100.50 10.8.0.1 &
exec openvpn --port 1194 --proto udp --dev tun --topology subnet \
  --server 10.8.0.0 255.255.255.0 \
  --ca /pki/ca.crt --cert /pki/server.crt --key /pki/server.key --dh none \
  --verify-client-cert none --username-as-common-name \
  --script-security 3 --auth-user-pass-verify /pki/ok.sh via-env \
  --data-ciphers AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305 \
  --push "dhcp-option DNS 10.8.0.1" --keepalive 5 20 --verb 3
