#!/usr/bin/env bash
# Linux attack chain, executed via VM Run Command (root).
# Generates: sshd invalid-user bursts -> useradd -> usermod -aG sudo -> userdel
for i in $(seq 1 12); do
  ssh -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
      -o ConnectTimeout=5 "svc_backup$((i % 4))@127.0.0.1" true >/dev/null 2>&1 || true
done
echo "12 failed ssh attempts against 127.0.0.1"

useradd -m -s /bin/bash -c "detection-lab simulation" simuser
usermod -aG sudo simuser
echo "created simuser and added to sudo"

sleep 60
userdel -r simuser 2>/dev/null || true
echo "cleanup done"
