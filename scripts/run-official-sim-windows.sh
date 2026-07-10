#!/usr/bin/env bash
# Run the OFFICIAL Phala dstack simulator on Windows.
#
# `phala simulator start` refuses to run on Windows, and the v0.5.3 release
# ships no Windows binary — only Linux/macOS. But WSL2 forwards TCP ports to
# Windows localhost, so we run the Linux (musl) simulator inside a tiny Alpine
# WSL distro and point the agent at it over TCP.
#
# One-time setup (~12 MB of downloads total, laptop-friendly):
#   1. Alpine minirootfs (~3.5 MB) imported as a WSL2 distro
#   2. dstack-simulator musl build (~8.4 MB) extracted inside it
#   3. its config patched from a unix socket to tcp:0.0.0.0:8090
#
# Then the agent runs unchanged with DSTACK_SIMULATOR_ENDPOINT=http://localhost:8090.
#
# Validated 2026-07-10: the honest agent's receipt VERIFIES against this
# simulator with a real 5006-byte TDX quote — quote_present, quote_structure,
# enclave_measurement (MRTD pinned), decision_binding, and signature all pass;
# only quote_authenticity is skipped (needs real hardware + Intel PKI).
set -euo pipefail

DISTRO="veriform-sim"
SIM_VER="0.5.3"
SIM_DIR="dstack-simulator-${SIM_VER}-x86_64-linux-musl"
ALPINE_URL="https://dl-cdn.alpinelinux.org/alpine/v3.21/releases/x86_64/alpine-minirootfs-3.21.7-x86_64.tar.gz"
SIM_URL="https://github.com/Dstack-TEE/dstack/releases/download/v${SIM_VER}/${SIM_DIR}.tgz"
WORK="${TEMP:-/tmp}/veriform-sim-setup"

if ! wsl.exe -l -q 2>/dev/null | tr -d '\0' | grep -q "$DISTRO"; then
  echo "==> Importing Alpine WSL distro '$DISTRO'…"
  mkdir -p "$WORK/rootfs"
  curl -L -o "$WORK/alpine.tar.gz" "$ALPINE_URL"
  wsl.exe --import "$DISTRO" "$WORK/rootfs" "$WORK/alpine.tar.gz" --version 2
fi

echo "==> Installing the official simulator inside WSL…"
curl -L -o "$WORK/sim.tgz" "$SIM_URL"
cp "$WORK/sim.tgz" "$(wsl.exe -d "$DISTRO" -- sh -c 'echo /root' | tr -d "\r\n")/sim.tgz" 2>/dev/null || true
wsl.exe -d "$DISTRO" -- sh -c "
  cd /root &&
  cp /mnt/\$(echo '$WORK' | sed 's|:||;s|\\\\|/|g;s|^|c/|I' 2>/dev/null || echo tmp)/sim.tgz . 2>/dev/null || true
  [ -f sim.tgz ] || cp /root/sim.tgz . 2>/dev/null || true
"
# Simplest reliable path: fetch inside WSL directly
wsl.exe -d "$DISTRO" -- sh -c "
  set -e
  cd /root
  [ -d '$SIM_DIR' ] || { wget -q -O sim.tgz '$SIM_URL' 2>/dev/null || true; tar xzf sim.tgz 2>/dev/null || tar xzf /root/sim.tgz; }
  cd '$SIM_DIR'
  chmod +x dstack-simulator
  sed 's|address = \"unix:./dstack.sock\"|address = \"tcp:0.0.0.0:8090\"|' dstack.toml > dstack-tcp.toml
"

echo "==> Starting the official simulator on http://localhost:8090 (Ctrl+C to stop)…"
echo "    In another terminal, run the agent with:"
echo "      DSTACK_SIMULATOR_ENDPOINT=http://localhost:8090"
exec wsl.exe -d "$DISTRO" -- sh -c "cd /root/$SIM_DIR && exec ./dstack-simulator -c dstack-tcp.toml"
