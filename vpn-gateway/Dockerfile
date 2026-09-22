# Axiom student VPN gateway: WireGuard endpoint that lab networks attach to.
# Lets personal Kali VMs reach their own lab targets directly (HTB/THM-style).
# Minimal image: wireguard-tools + iptables only. The Axiom app drives this
# container via `docker exec` (wg peer management, per-student firewall rules)
# exactly like it already drives lab networks through the Docker socket.
FROM debian:bookworm-slim
RUN apt-get update \
  && apt-get install -y --no-install-recommends wireguard-tools iptables iproute2 \
  && rm -rf /var/lib/apt/lists/*
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh
EXPOSE 51820/udp
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
