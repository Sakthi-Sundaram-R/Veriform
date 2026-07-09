"""Receipt verification — the layer that turns a raw quote into ✅/❌.

Checks, in order:
  1. quote present
  2. quote parses as a TDX-quote-sized structure
  3. report_data inside the quote matches sha256(decision_hash || address)
     — proves THIS decision was bound inside THE enclave
  4. signature over the canonical payload recovers to the claimed address
  5. quote authenticity against a verification endpoint (real TDX only;
     skipped in simulator/dev mode, reported honestly as such)

Any hard failure in 1-4 => REJECTED. Check 5 upgrades trust when available.
"""

import hashlib
import json
import os

import httpx
from eth_account import Account
from eth_account.messages import encode_defunct

# TDX quote v4: 48-byte header + TD report body; report_data is the final
# 64 bytes of the 584-byte body => absolute offset 568..632.
REPORT_DATA_OFFSET = 568
REPORT_DATA_END = 632

PHALA_VERIFY_URL = os.environ.get("PHALA_VERIFY_URL", "")


def canonical_bytes(payload: dict) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()


def expected_binding(payload: dict, address: str) -> bytes:
    decision_hash = hashlib.sha256(canonical_bytes(payload)).digest()
    return hashlib.sha256(decision_hash + address.lower().encode()).digest()


def verify_receipt(payload: dict, address: str, signature: str, quote: str | None) -> dict:
    checks = []
    hard_fail = False

    # 1. Quote present
    if not quote:
        checks.append(_check("quote_present", False, "no attestation quote in response"))
        hard_fail = True
    else:
        checks.append(_check("quote_present", True, "attestation quote included"))

    # 2. Quote structure
    quote_bytes = b""
    if quote:
        try:
            quote_bytes = bytes.fromhex(quote.removeprefix("0x"))
            ok = len(quote_bytes) >= REPORT_DATA_END
            checks.append(
                _check(
                    "quote_structure",
                    ok,
                    f"quote is {len(quote_bytes)} bytes"
                    + ("" if ok else f" (need >= {REPORT_DATA_END})"),
                )
            )
            hard_fail |= not ok
        except ValueError:
            checks.append(_check("quote_structure", False, "quote is not valid hex"))
            hard_fail = True

    # 3. Decision binding: report_data must commit to this exact decision
    if len(quote_bytes) >= REPORT_DATA_END:
        report_data = quote_bytes[REPORT_DATA_OFFSET:REPORT_DATA_END]
        ok = report_data[:32] == expected_binding(payload, address)
        checks.append(
            _check(
                "decision_binding",
                ok,
                "report_data commits to this decision + key"
                if ok
                else "report_data does NOT match this decision — decision was not produced in the attested enclave",
            )
        )
        hard_fail |= not ok

    # 4. Signature
    try:
        recovered = Account.recover_message(
            encode_defunct(canonical_bytes(payload)),
            signature=bytes.fromhex(signature.removeprefix("0x")),
        )
        ok = recovered.lower() == address.lower()
        checks.append(
            _check(
                "signature",
                ok,
                "signature recovers to the agent's key"
                if ok
                else f"signature recovers to {recovered}, not {address}",
            )
        )
        hard_fail |= not ok
    except Exception as exc:
        checks.append(_check("signature", False, f"signature invalid: {exc}"))
        hard_fail = True

    # 5. Quote authenticity (real hardware attestation chain)
    if quote and not hard_fail:
        auth = _authenticity_check(quote)
        checks.append(auth)
        hard_fail |= auth["passed"] is False

    verified = not hard_fail
    return {
        "verified": verified,
        "verdict": "VERIFIED" if verified else "REJECTED",
        "checks": checks,
    }


def _authenticity_check(quote: str) -> dict:
    if not PHALA_VERIFY_URL:
        return {
            "name": "quote_authenticity",
            "passed": None,
            "detail": "skipped — simulator/dev mode (set PHALA_VERIFY_URL after deploying to real TDX)",
        }
    try:
        resp = httpx.post(PHALA_VERIFY_URL, json={"hex": quote}, timeout=20)
        ok = resp.status_code == 200 and resp.json().get("success", False)
        return _check(
            "quote_authenticity",
            ok,
            "genuine hardware attestation chain" if ok else f"verification endpoint rejected quote: {resp.text[:200]}",
        )
    except Exception as exc:
        return _check("quote_authenticity", False, f"verification endpoint unreachable: {exc}")


def _check(name: str, passed: bool, detail: str) -> dict:
    return {"name": name, "passed": passed, "detail": detail}
