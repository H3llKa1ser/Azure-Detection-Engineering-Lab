#!/usr/bin/env bash
# Network attack-chain payload, run on the Linux victim via VM Run Command.
# Generates flows that VNet flow logs capture and Traffic Analytics enriches:
#   NET-001 vertical port scan, NET-002 host sweep, NET-003 east-west mgmt,
#   NET-005 outbound transfer. (NET-004 malicious-flow is driven separately.)
#
# Everything targets the lab's own subnet and ordinary public endpoints; no
# exploitation, only connection attempts and a measured download.
set -uo pipefail

SUBNET_PREFIX="${SUBNET_PREFIX:-10.42.1}"
SELF="$(hostname -I | tr ' ' '\n' | grep "^${SUBNET_PREFIX}\." | head -1)"
echo "self=${SELF:-unknown} subnet=${SUBNET_PREFIX}.0/24"

command -v nc >/dev/null 2>&1 || { apt-get update -qq && apt-get install -y -qq netcat-openbsd >/dev/null 2>&1; }

scan() { # host, timeout, ports...
  local host="$1" to="$2"; shift 2
  for p in "$@"; do
    if timeout "$to" bash -c "echo > /dev/tcp/${host}/${p}" 2>/dev/null; then echo "  open ${host}:${p}"; fi
  done
}

# NET-001: vertical scan - many ports against the default gateway (.1).
echo "[net-001] vertical port scan against ${SUBNET_PREFIX}.1"
scan "${SUBNET_PREFIX}.1" 0.3 $(seq 1 150)

# NET-002: horizontal sweep - one port across many hosts in the subnet.
echo "[net-002] host sweep across ${SUBNET_PREFIX}.4-40 on tcp/445"
for h in $(seq 4 40); do timeout 0.3 bash -c "echo > /dev/tcp/${SUBNET_PREFIX}.${h}/445" 2>/dev/null || true; done

# NET-003: east-west management ports against other hosts in the subnet.
echo "[net-003] east-west management-port connections"
for h in $(seq 4 12); do
  scan "${SUBNET_PREFIX}.${h}" 0.3 22 3389 445 5985
done

# NET-005: measured outbound transfer to a public endpoint (~120 MB).
echo "[net-005] outbound transfer to public endpoint"
curl -s -o /dev/null --max-time 120 "https://speed.cloudflare.com/__down?bytes=125829120" \
  && echo "  transferred ~120MB" || echo "  transfer skipped (no egress)"

echo "[net] done - Traffic Analytics processes flows every ${TA_INTERVAL:-10}-60 min"
