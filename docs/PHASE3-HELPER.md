# Phase 3 helper — run one block on any Intel TDX VM

Veriform's live-silicon step (Phase 3) needs a genuine Intel TDX quote generated
over one of our decisions. That requires real TDX hardware — but it doesn't have
to be *your* hardware. **Anyone with an Intel TDX VM can run the block below and
send back the output.** The result is cryptographically self-standing: it's a
real Intel DCAP chain of trust over a Veriform decision, so it proves genuine
silicon signed our binding no matter whose VM produced it.

## For the helper

You need an **Intel TDX guest** — GCP `c3-standard`, Azure `DCesv6`/`ECesv6`, or
any KVM TDX VM — running **Ubuntu 24.04 (kernel ≥ 6.7)**. Takes ~2 minutes and
costs nothing. It's a public repo and a read-only demo — nothing is installed
system-wide beyond `git`/`python3-venv`, and no secrets are touched.

Paste this into the VM, then send back everything it prints after
`COPY EVERYTHING BELOW`:

```bash
# ── Veriform Phase 3 · run on any Intel TDX VM · ~2 minutes ─────────────
# Generates a genuine TDX quote over a Veriform decision and verifies the
# full Intel chain of trust. Prints the result at the end to copy back.
sudo apt-get update -qq && sudo apt-get install -y -qq git python3-venv >/dev/null 2>&1

# Confirm this is really a TDX guest
if [ ! -d /sys/kernel/config/tsm/report ]; then
  sudo modprobe tsm 2>/dev/null || true
  sudo mount -t configfs none /sys/kernel/config 2>/dev/null || true
fi
if [ ! -d /sys/kernel/config/tsm/report ]; then
  echo "!! Not an Intel TDX VM (no /sys/kernel/config/tsm/report). Need a TDX guest, kernel >= 6.7."
  exit 1
fi

rm -rf /tmp/veriform && git clone --depth 1 https://github.com/Sakthi-Sundaram-R/Veriform.git /tmp/veriform
cd /tmp/veriform
bash scripts/tdx-quote.sh || echo "(script reported an issue — sending output anyway)"

echo
echo "========== COPY EVERYTHING BELOW THIS LINE AND SEND IT BACK =========="
echo "----- PROOF (result summary) -----"
cat docs/phase3-real-quote-proof.json 2>/dev/null || echo "no proof file produced"
echo
echo "----- QUOTE HEX (the raw hardware quote) -----"
cat docs/phase3-real-quote.hex 2>/dev/null || echo "no quote file produced"
echo "========== END =========="
```

## What comes back, and what to do with it

The output has two parts:

1. **PROOF** — a JSON summary. Every DCAP link (`att_key_signs_report`,
   `qe_binds_att_key`, `pck_signs_qe`, `chain_to_intel_root`) plus
   `decision_binding` showing `PASS` **is Phase 3 complete**.

2. **QUOTE HEX** — the raw hardware quote. Save it as
   `docs/real_tdx_quote_live.hex` and **re-verify it yourself**, so you don't
   have to trust the helper's word:

   ```bash
   python -c "import sys; sys.path.insert(0,'verifier'); from app.dcap import verify_full_dcap; import json; print(json.dumps(verify_full_dcap(open('docs/real_tdx_quote_live.hex').read().strip()), indent=2))"
   ```

   `"ok": true` with every link passing means a genuine Intel TDX quote over our
   own `report_data` verified end to end on your machine.

## Note on the cert chain

If the run fails only at `chain_to_intel_root` with an empty PCK chain, the cloud
quote is using `cert_type 5` (collateral referenced out-of-band) rather than
inlining the PEM chain — see [`verifier/app/dcap.py`](../verifier/app/dcap.py).
That's a known, small follow-up (fetch the chain from Intel PCS), not a redesign;
send the output and it can be added against the real quote.
