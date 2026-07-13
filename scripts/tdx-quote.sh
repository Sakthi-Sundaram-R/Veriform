#!/usr/bin/env bash
# Phase 3, cloud-agnostic: on ANY Intel TDX VM, generate a genuine quote over
# our own decision's report_data and verify the full Intel chain of trust.
# No Phala, no Docker, no paid service — just a TDX guest.
#
#   Provision any Intel TDX VM (GCP c3-standard, Azure DCesv6, ...), then:
#     git clone <this repo> && cd Veriform
#     bash scripts/tdx-quote.sh
#
# On success it prints all DCAP links PASS and writes:
#     docs/phase3-real-quote.hex          the genuine quote
#     docs/phase3-real-quote-proof.json   the full verification result
set -euo pipefail
cd "$(dirname "$0")/.."

TSM=/sys/kernel/config/tsm/report

echo "==> Checking for the Intel TDX TSM interface ($TSM)…"
if [ ! -d "$TSM" ]; then
  echo "    not present; attempting to load the module + mount configfs…"
  sudo modprobe tsm 2>/dev/null || true
  sudo mount -t configfs none /sys/kernel/config 2>/dev/null || true
fi
if [ ! -d "$TSM" ]; then
  cat >&2 <<'ERR'
ERROR: no TDX TSM report interface found.
       This script must run INSIDE a real Intel TDX guest (GCP c3-standard,
       Azure DCesv6/ECesv6, or any KVM TDX VM) with a Linux kernel >= 6.7.
       It cannot run on a laptop or a non-TDX VM.
ERR
  exit 1
fi
echo "    OK."

echo "==> Setting up a Python environment…"
python3 -m venv .venv-tdx
# shellcheck disable=SC1091
. .venv-tdx/bin/activate
pip install -q --upgrade pip
# eth-account (enclave signing), cryptography (dcap chain checks),
# httpx (verify.py imports it at module load).
pip install -q eth-account cryptography httpx

echo "==> Generating a real TDX quote over our decision and verifying it…"
QUOTE_BACKEND=tsm python3 scripts/_tdx_quote.py
