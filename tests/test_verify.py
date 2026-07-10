"""Verifier pipeline tests: honest receipts verify, every tamper vector fails.

Quotes here are built the same way the dstack simulator / dev shim builds
them: structurally valid TDX layout with report_data at the right offset,
no hardware chain (the authenticity check is out of scope locally).
"""

import secrets
from pathlib import Path

from eth_account import Account
from eth_account.messages import encode_defunct

from conftest import load_module

V = load_module("veriform_verify", "verifier/app/verify.py")

# Real Intel PCK chain (from the official simulator) so synthetic quotes pass
# the authenticity check; these tests exercise binding/signature/MRTD.
_FIXTURE = bytes.fromhex(
    (Path(__file__).parent / "fixtures" / "official_sim_quote.hex").read_text().strip()
)
_CHAIN = _FIXTURE[_FIXTURE.find(b"-----BEGIN CERTIFICATE-----"):]


PAYLOAD = {
    "agent": "veriform-agent/0.1",
    "request": {
        "to": "0x1111111111111111111111111111111111111111",
        "amount": 0.5,
        "token": "ETH",
        "reason": "pay invoice",
    },
    "action": "APPROVE",
    "method": "rules",
    "notes": "trusted recipient",
    "timestamp": "2026-07-10T00:00:00+00:00",
}


def make_receipt(payload, mrtd=b"\x00" * 48):
    """Build receipt parts exactly the way the honest agent does."""
    acct = Account.from_key(secrets.token_bytes(32))
    report_data = V.expected_binding(payload, acct.address) + b"\x00" * 32
    quote = bytearray(700)
    quote[V.MRTD_OFFSET:V.MRTD_END] = mrtd
    quote[V.REPORT_DATA_OFFSET:V.REPORT_DATA_END] = report_data
    quote += _CHAIN  # append the real Intel chain so authenticity passes
    sig = acct.sign_message(encode_defunct(V.canonical_bytes(payload))).signature.hex()
    return acct, sig, bytes(quote).hex()


def failed_checks(result):
    return [c["name"] for c in result["checks"] if c["passed"] is False]


def test_honest_receipt_verifies():
    acct, sig, quote = make_receipt(PAYLOAD)
    result = V.verify_receipt(PAYLOAD, acct.address, sig, quote)
    assert result["verified"], result
    assert result["verdict"] == "VERIFIED"


def test_tampered_payload_rejected():
    acct, sig, quote = make_receipt(PAYLOAD)
    tampered = dict(PAYLOAD, action="DENY")
    result = V.verify_receipt(tampered, acct.address, sig, quote)
    assert not result["verified"]
    assert set(failed_checks(result)) == {"decision_binding", "signature"}


def test_missing_quote_rejected():
    acct, sig, _ = make_receipt(PAYLOAD)
    result = V.verify_receipt(PAYLOAD, acct.address, sig, None)
    assert not result["verified"]
    assert failed_checks(result) == ["quote_present"]


def test_forged_quote_rejected():
    acct, sig, _ = make_receipt(PAYLOAD)
    forged = (b"\xde\xad" * 316).hex()  # right size, garbage content
    result = V.verify_receipt(PAYLOAD, acct.address, sig, forged)
    assert not result["verified"]
    assert "decision_binding" in failed_checks(result)


def test_wrong_signer_rejected():
    acct, _, quote = make_receipt(PAYLOAD)
    outsider = Account.from_key(secrets.token_bytes(32))
    bad_sig = outsider.sign_message(
        encode_defunct(V.canonical_bytes(PAYLOAD))
    ).signature.hex()
    result = V.verify_receipt(PAYLOAD, acct.address, bad_sig, quote)
    assert not result["verified"]
    assert failed_checks(result) == ["signature"]


def test_malformed_quote_rejected():
    acct, sig, _ = make_receipt(PAYLOAD)
    result = V.verify_receipt(PAYLOAD, acct.address, sig, "not-hex-at-all")
    assert not result["verified"]
    assert "quote_structure" in failed_checks(result)


def test_short_quote_rejected():
    acct, sig, _ = make_receipt(PAYLOAD)
    result = V.verify_receipt(PAYLOAD, acct.address, sig, "ab" * 100)
    assert not result["verified"]
    assert "quote_structure" in failed_checks(result)


class TestMeasurementPinning:
    def test_skipped_when_not_pinned(self, monkeypatch):
        monkeypatch.setattr(V, "EXPECTED_MRTD", "")
        acct, sig, quote = make_receipt(PAYLOAD)
        result = V.verify_receipt(PAYLOAD, acct.address, sig, quote)
        assert result["verified"]
        check = next(c for c in result["checks"] if c["name"] == "enclave_measurement")
        assert check["passed"] is None

    def test_matching_mrtd_passes(self, monkeypatch):
        mrtd = secrets.token_bytes(48)
        monkeypatch.setattr(V, "EXPECTED_MRTD", mrtd.hex())
        acct, sig, quote = make_receipt(PAYLOAD, mrtd=mrtd)
        result = V.verify_receipt(PAYLOAD, acct.address, sig, quote)
        assert result["verified"]
        check = next(c for c in result["checks"] if c["name"] == "enclave_measurement")
        assert check["passed"] is True

    def test_wrong_mrtd_rejected(self, monkeypatch):
        monkeypatch.setattr(V, "EXPECTED_MRTD", "ff" * 48)
        acct, sig, quote = make_receipt(PAYLOAD, mrtd=b"\x00" * 48)
        result = V.verify_receipt(PAYLOAD, acct.address, sig, quote)
        assert not result["verified"]
        assert "enclave_measurement" in failed_checks(result)
