# The image inside the Barrier package (built by synology/build-spk.sh).
FROM python:3.12-alpine
# openvpn: the VPN client. iptables(+legacy): the kill switch (Synology's kernel
# has no nf_tables). kmod: loads the NAS's tun module. tini: forwards stop signals.
RUN apk add --no-cache openvpn iptables iptables-legacy ca-certificates tzdata kmod tini \
 && pip install --no-cache-dir flask==3.* waitress==3.*
COPY app /opt/barrier/app
COPY entrypoint.sh /entrypoint.sh
RUN chmod 755 /entrypoint.sh /opt/barrier/app/scripts/*.sh
ENV CONFIG_DIR=/config PORT=8085 PYTHONUNBUFFERED=1 BARRIER_UPDATE_DIR=/config/app-update
EXPOSE 8085
ENTRYPOINT ["/sbin/tini", "--", "/entrypoint.sh"]
