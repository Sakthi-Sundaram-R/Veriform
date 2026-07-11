"""Full Intel TDX DCAP verification, proven against a REAL captured hardware
quote: the complete chain of trust (Intel Root -> PCK -> QE -> attestation key
-> TD report) validates, and any tampering with the signed report is caught.
"""

from pathlib import Path

from conftest import load_module

DCAP = load_module("veriform_dcap", "verifier/app/dcap.py")

REAL_QUOTE = (Path(__file__).parent / "fixtures" / "real_tdx_quote.hex").read_text().strip()


def test_real_hardware_quote_passes_full_dcap():
    res = DCAP.verify_full_dcap(REAL_QUOTE)
    assert res["ok"], [c for c in res["checks"] if not c["passed"]]
    names = {c["name"] for c in res["checks"] if c["passed"]}
    # every link in the chain of trust verified
    assert {"att_key_signs_report", "qe_binds_att_key",
            "pck_signs_qe", "chain_to_intel_root"} <= names


def test_tampered_report_fails_att_key_signature():
    q = bytearray(bytes.fromhex(REAL_QUOTE))
    q[600] ^= 0xFF  # flip a byte inside the signed TD report (report_data region)
    res = DCAP.verify_full_dcap(bytes(q).hex())
    assert not res["ok"]
    first_fail = next(c for c in res["checks"] if not c["passed"])
    assert first_fail["name"] == "att_key_signs_report"


def test_tampered_qe_report_fails():
    q = bytearray(bytes.fromhex(REAL_QUOTE))
    q[900] ^= 0xFF  # flip a byte inside the QE report
    res = DCAP.verify_full_dcap(bytes(q).hex())
    assert not res["ok"]


def test_garbage_quote_rejected():
    res = DCAP.verify_full_dcap("dead" * 400)
    assert not res["ok"]


def test_non_hex_rejected():
    res = DCAP.verify_full_dcap("not-a-quote")
    assert not res["ok"]
