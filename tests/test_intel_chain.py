"""The free quote_authenticity check: a real Intel PCK chain (captured from
the official dstack simulator) validates to the Intel SGX Root CA; a forged
or chainless quote does not.

What this proves: the quote carries genuine Intel-signed attestation
collateral rooted in Intel's published SGX Root CA. What it does NOT prove
(the real-hardware delta, gated behind PHALA_VERIFY_URL): that the quote
BODY signature over report_data was produced by that Intel-certified key —
the simulator patches report_data in after capture, so only unpatched
hardware output carries a valid body signature.
"""

from pathlib import Path

from conftest import load_module

V = load_module("veriform_verify_chain", "verifier/app/verify.py")

FIXTURE = Path(__file__).parent / "fixtures" / "official_sim_quote.hex"


def test_real_intel_chain_passes():
    quote = FIXTURE.read_text().strip()
    result = V._intel_chain_check(quote)
    assert result["passed"] is True, result
    assert "Intel" in result["detail"]


def test_forged_quote_has_no_chain():
    forged = ("dead" * 316)  # right-ish size, no Intel certificate chain
    result = V._intel_chain_check(forged)
    assert result["passed"] is False
    assert "no Intel certificate chain" in result["detail"]


def test_tampered_chain_fails_to_root():
    # Flip a byte inside the PEM chain so the root fingerprint no longer
    # matches Intel's pinned SGX Root CA (or a signature link breaks).
    raw = bytearray(bytes.fromhex(FIXTURE.read_text().strip()))
    start = bytes(raw).find(b"-----END CERTIFICATE-----")  # inside the last (root) cert
    raw[start - 40] ^= 0xFF
    result = V._intel_chain_check(bytes(raw).hex())
    assert result["passed"] is False
