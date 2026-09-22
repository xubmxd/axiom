#!/bin/sh
# Axiom VPN gateway entrypoint: bring up wg0, enforce a default-drop
# forwarding policy, then idle. The Axiom app manages WireGuard peers and
# per-student ACCEPT rules at runtime via `docker exec` (rules carry the
# `axiom-vpn:` comment marker so they can be listed and purged safely).
set -eu

BASE="${VPN_SUBNET_BASE:-10.212}"
GATEWAY_IP="${BASE}.0.1"
WG_PORT="${WG_PORT:-51820}"
CFG_DIR="/config"
mkdir -p "$CFG_DIR"

log() { echo "[vpn-gateway] $*"; }

# Persistent gateway identity (survives container recreation via volume).
if [ ! -f "$CFG_DIR/server_private.key" ]; then
  log "generating gateway keypair"
  umask 077
  wg genkey | tee "$CFG_DIR/server_private.key" | wg pubkey > "$CFG_DIR/server_public.key"
fi
SERVER_PUB="$(cat "$CFG_DIR/server_public.key")"
log "gateway public key: $SERVER_PUB"

# Forwarding on (compose also sets the sysctl; keep a best-effort copy here).
sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1 || true

# Bring up wg0: kernel module path first, userspace fallback if present.
WG_UP=0
if ! ip link show wg0 >/dev/null 2>&1; then
  if ip link add dev wg0 type wireguard 2>/dev/null; then
    WG_UP=1
  elif command -v wireguard-go >/dev/null 2>&1; then
    log "kernel wireguard unavailable, using wireguard-go fallback"
    (wireguard-go wg0 >/dev/null 2>&1 &) || true
    for _ in 1 2 3 4 5; do
      ip link show wg0 >/dev/null 2>&1 && { WG_UP=1; break; }
      sleep 1
    done
  fi
else
  WG_UP=1
fi

if [ "$WG_UP" = "1" ]; then
  ip addr add "$GATEWAY_IP/24" dev wg0 2>/dev/null || true
  ip link set mtu 1380 dev wg0 2>/dev/null || true
  wg set wg0 listen-port "$WG_PORT" private-key "$CFG_DIR/server_private.key" 2>/dev/null || \
    log "WARNING: could not configure wg0 (missing NET_ADMIN?)"
  ip link set up dev wg0 2>/dev/null || true
  log "wg0 up at $GATEWAY_IP/24 port $WG_PORT"
else
  log "FATAL: no wireguard dataplane available (need host wireguard module or wireguard-go)."
  log "Container stays alive in DEGRADED state so the app can report it; VPN traffic will not flow."
fi

# Default-drop forwarding inside this netns; return traffic always allowed.
# Per-student rules are appended by the app: -i wg0 -s <client/32>
# -d <own-target/32> (-p tcp / -p udp / -p icmp), tagged axiom-vpn:<user>.
iptables -P FORWARD DROP 2>/dev/null || true
iptables -C FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || \
  iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || true

# Return-path fix (required): lab targets answer via their bridge's host
# gateway, which knows nothing of the VPN subnet. NAT VPN-originated
# traffic to the gateway's lab-net address so replies come back here and
# are un-NATed to the student. Without this, handshakes complete but no
# lab traffic flows — the classic Docker-VPN asymmetry.
iptables -t nat -C POSTROUTING -s "$BASE.0.0/24" -j MASQUERADE 2>/dev/null || \
  iptables -t nat -A POSTROUTING -s "$BASE.0.0/24" -j MASQUERADE 2>/dev/null || true

log "ready"
exec sleep infinity
