"""Phase 3 proof (cloud-agnostic): on a real Intel TDX VM, produce a genuine
quote over OUR OWN decision's report_data and verify the full chain of trust.

Run via scripts/tdx-quote.sh (which checks the TSM interface first), or directly
on a TDX guest with QUOTE_BACKEND=tsm set.

What this proves that a simulator cannot: the attestation key baked into real
silicon signs a TD report containing exactly our report_data, so the verifier's
`att_key_signs_report` link passes over our own decision — the one guarantee the
sim can't give (it patches report_data after capture).

Key note: on a generic TDX VM there is no dstack-sealed key, so we sign the
decision with an ephemeral key here. The Phase-3 guarantee (real hardware signed
our report_data) does not depend on how the signing key is derived; a production
deploy would swap in a sealed/enclave-derived key.
"""

import importlib.util
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _load(alias, relpath):
    spec = importlib.util.spec_from_file_location(alias, ROOT / relpath)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[alias] = mod
    spec.loader.exec_module(mod)
    return mod


def main() -> int:
    os.environ.setdefault("QUOTE_BACKEND", "tsm")

    enclave = _load("veriform_enclave", "agent/app/enclave.py")
    dcap = _load("veriform_dcap", "verifier/app/dcap.py")
    verify = _load("veriform_verify", "verifier/app/verify.py")

    if enclave.resolve_quote_backend() != "tsm":
        print("ERROR: set QUOTE_BACKEND=tsm to generate a real TDX quote.")
        return 2

    # A concrete decision to bind — the same shape the agent attests.
    from eth_account import Account

    account = Account.create()  # ephemeral; see module docstring
    payload = {
        "action": "APPROVE",
        "amount": "2.0",
        "to": "0x1111111111111111111111111111111111111111",
        "reason": "Phase 3 live-silicon attestation proof",
    }
    report_data = enclave.expected_report_data(payload, account.address)

    print(f"==> Requesting a TDX quote over report_data ({len(report_data)} bytes)…")
    quote_hex = enclave.tsm_get_quote(report_data)
    print(f"    got a {len(quote_hex)//2}-byte quote from real hardware.")

    # 1. Full DCAP: every link of the Intel chain of trust over our report.
    dcap_res = dcap.verify_full_dcap(quote_hex)

    # 2. Decision binding: report_data in the quote commits to THIS decision.
    rd = bytes.fromhex(quote_hex)[verify.REPORT_DATA_OFFSET:verify.REPORT_DATA_END]
    binding_ok = rd[:32] == verify.expected_binding(payload, account.address)

    print("\n==> Full DCAP chain of trust:")
    for c in dcap_res["checks"]:
        print(f"    [{'PASS' if c['passed'] else 'FAIL'}] {c['name']}: {c['detail']}")
    print(f"\n==> decision_binding (report_data commits to our decision): "
          f"{'PASS' if binding_ok else 'FAIL'}")

    all_ok = dcap_res["ok"] and binding_ok

    out = ROOT / "docs"
    out.mkdir(exist_ok=True)
    (out / "phase3-real-quote.hex").write_text(quote_hex)
    (out / "phase3-real-quote-proof.json").write_text(json.dumps({
        "ok": all_ok,
        "address": account.address,
        "payload": payload,
        "report_data_hex": report_data.hex(),
        "quote_bytes": len(quote_hex) // 2,
        "dcap": dcap_res,
        "decision_binding": binding_ok,
    }, indent=2))
    print(f"\n==> Saved quote + proof to {out}/phase3-real-quote*.{{hex,json}}")

    if all_ok:
        print("\n✅ PHASE 3 COMPLETE: a genuine Intel TDX quote over our own "
              "decision passed the full chain of trust on real silicon.")
        return 0
    print("\n❌ Verification did not fully pass — see the checks above.")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
