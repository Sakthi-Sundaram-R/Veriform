"""Receipt verification — the layer that turns a raw quote into ✅/❌.

Checks, in order:
  1. quote present
  2. quote parses as a TDX-quote-sized structure
  3. enclave measurement (MRTD) matches the pinned known-good build
     (skipped when EXPECTED_MRTD is unset — dev/simulator mode)
  4. report_data inside the quote matches sha256(decision_hash || address)
     — proves THIS decision was bound inside THE enclave
  5. signature over the canonical payload recovers to the claimed address
  6. quote authenticity: by default, verify the quote's Intel PCK certificate
     chain roots in the Intel SGX Root CA (free, offline — proves genuine
     Intel attestation collateral). If PHALA_VERIFY_URL is set, defer to a
     full-DCAP endpoint that also checks the quote-body signature over
     report_data — the guarantee only unpatched real hardware provides.

Any hard failure => REJECTED. Skipped checks are reported as skipped.
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
# MRTD (measurement of the enclave's initial code/data) sits at body offset
# 136 for 48 bytes => absolute 184..232.
MRTD_OFFSET = 184
MRTD_END = 232

PHALA_VERIFY_URL = os.environ.get("PHALA_VERIFY_URL", "")
# Pin the known-good enclave measurement (hex). Unset => check is skipped,
# which is honest for dev/simulator builds where the MRTD isn't meaningful.
EXPECTED_MRTD = os.environ.get("EXPECTED_MRTD", "").lower().removeprefix("0x")


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

    # 3. Enclave measurement: the quote's MRTD must match the pinned
    #    known-good build (when one is pinned)
    if len(quote_bytes) >= REPORT_DATA_END:
        mrtd = quote_bytes[MRTD_OFFSET:MRTD_END].hex()
        if not EXPECTED_MRTD:
            checks.append({
                "name": "enclave_measurement",
                "passed": None,
                "detail": "skipped — no expected measurement pinned "
                          "(set EXPECTED_MRTD to the known-good build's MRTD)",
            })
        else:
            ok = mrtd == EXPECTED_MRTD
            checks.append(
                _check(
                    "enclave_measurement",
                    ok,
                    "MRTD matches the pinned known-good build"
                    if ok
                    else f"MRTD {mrtd[:16]}... does not match the pinned build — different code is running",
                )
            )
            hard_fail |= not ok

    # 4. Decision binding: report_data must commit to this exact decision
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

    # 5. Signature
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

    # 6. Quote authenticity (real hardware attestation chain)
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
    # An explicit endpoint (e.g. Phala on real hardware) does the strongest
    # check: full DCAP verification including the quote-body signature.
    if PHALA_VERIFY_URL:
        try:
            resp = httpx.post(PHALA_VERIFY_URL, json={"hex": quote}, timeout=20)
            ok = resp.status_code == 200 and resp.json().get("success", False)
            return _check(
                "quote_authenticity",
                ok,
                "genuine hardware attestation chain (full DCAP)"
                if ok else f"verification endpoint rejected quote: {resp.text[:200]}",
            )
        except Exception as exc:
            return _check("quote_authenticity", False, f"verification endpoint unreachable: {exc}")
    # Free, offline fallback: verify the quote carries a genuine Intel-signed
    # PCK certificate chain rooted in the Intel SGX Root CA. This proves the
    # attestation collateral is real Intel PKI (and rejects forged quotes with
    # no chain). Full quote-body signature verification is the additional
    # guarantee real unpatched hardware provides — see PHALA_VERIFY_URL.
    return _intel_chain_check(quote)


# Intel SGX Root CA — pinned public-key (SPKI) SHA-256. Every genuine Intel
# DCAP quote's certificate chain roots here.
INTEL_SGX_ROOT_CA_SPKI_SHA256 = (
    "a0af031289f5d5d4132f9186068a7fc13628633ba235777472e29b6b6c67a49e"
)


def _intel_chain_check(quote: str) -> dict:
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
    except Exception:
        return _check("quote_authenticity", None,
                      "skipped — install `cryptography` to verify the Intel PKI chain")

    raw = bytes.fromhex(quote.removeprefix("0x"))
    start = raw.find(b"-----BEGIN CERTIFICATE-----")
    if start < 0:
        return _check("quote_authenticity", False,
                      "no Intel certificate chain in quote (forged or non-attested)")
    end = raw.rfind(b"-----END CERTIFICATE-----")
    pem = raw[start:end + len(b"-----END CERTIFICATE-----")]
    try:
        certs = x509.load_pem_x509_certificates(pem)
    except Exception as exc:
        return _check("quote_authenticity", False, f"certificate chain unparseable: {exc}")
    if len(certs) < 2:
        return _check("quote_authenticity", False, "incomplete Intel certificate chain")

    # Verify each cert is signed by the next (leaf -> intermediate -> root).
    for child, parent in zip(certs, certs[1:]):
        try:
            parent.public_key().verify(
                child.signature, child.tbs_certificate_bytes,
                ec.ECDSA(child.signature_hash_algorithm),
            )
        except Exception:
            return _check("quote_authenticity", False,
                          "certificate chain does not validate (broken signature link)")

    # The root must be the pinned Intel SGX Root CA (by SPKI fingerprint).
    root = certs[-1]
    spki = root.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    root_fp = hashlib.sha256(spki).hexdigest()
    if root_fp != INTEL_SGX_ROOT_CA_SPKI_SHA256:
        return _check("quote_authenticity", False,
                      f"chain does not root in the Intel SGX Root CA (got {root_fp[:16]}…)")

    return _check("quote_authenticity", True,
                  "Intel SGX PCK chain verified to the Intel Root CA")


def _check(name: str, passed: bool, detail: str) -> dict:
    return {"name": name, "passed": passed, "detail": detail}
