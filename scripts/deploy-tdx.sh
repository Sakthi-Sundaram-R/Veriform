#!/usr/bin/env bash
# Phase 3: deploy the agent to real Intel TDX, prove a genuine quote verifies,
# then tear down so the meter barely runs. Run after `phala login` and a
# Phala Cloud top-up.
#
#   bash scripts/deploy-tdx.sh
#
# Reads GEMINI_API_KEY from .env. Leaves the CVM running only if VERIFORM_KEEP=1.
set -euo pipefail

IMAGE="ghcr.io/sakthi-sundaram-r/veriform-agent:latest"
NAME="veriform-agent"
GEMINI_KEY="$(grep '^GEMINI_API_KEY=' .env | cut -d= -f2-)"

echo "==> Deploying $NAME to a TDX CVM (this provisions real hardware)…"
phala deploy -c docker-compose.phala.yaml -n "$NAME" \
  -e AGENT_IMAGE="$IMAGE" \
  -e GEMINI_API_KEY="$GEMINI_KEY" \
  -e JUDGE_PROVIDER=gemini \
  --wait --json | tee /tmp/veriform-deploy.json

CVM_ID="$(python -c "import json;print(json.load(open('/tmp/veriform-deploy.json')).get('cvm_id',''))" 2>/dev/null || true)"
echo "==> CVM: ${CVM_ID:-<see output above>}"

echo "==> Fetch the CVM's attestation (genuine Intel TDX quote):"
phala cvms attestation "$NAME" || phala cvms attestation "$CVM_ID" || true

cat <<'NOTE'

Next, point the verifier at the deployed agent URL and set:
    PHALA_VERIFY_URL   -> enables the quote_authenticity check against Intel PKI
    EXPECTED_MRTD      -> pin the measurement printed in the attestation above
Then run a /ask through the verifier and screenshot all 6 checks green.

NOTE

if [ "${VERIFORM_KEEP:-0}" != "1" ]; then
  echo "==> Tearing down the CVM (set VERIFORM_KEEP=1 to keep it running)…"
  phala cvms delete "$NAME" --yes 2>/dev/null || phala cvms delete "$CVM_ID" --yes 2>/dev/null || \
    echo "   (delete manually with: phala cvms delete $NAME)"
fi
echo "==> Done."
