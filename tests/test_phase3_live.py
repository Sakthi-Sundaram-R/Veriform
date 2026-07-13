"""Phase 3, DONE: the full Intel chain of trust over a quote produced on REAL
Phala Cloud TDX silicon (node prod9, US-WEST-1, tdx.small), bound to one of our
own agent decisions.

Unlike the simulator's captured quote, this one was signed by the enclave's
attestation key over a TD report containing OUR report_data — nothing was
patched after the fact. So `att_key_signs_report` passes here for the first time
on our own decision. This fixture is the evidence Phase 3 completed; the test
guards it from regressing.
"""

from pathlib import Path

from conftest import load_module

DCAP = load_module("veriform_dcap_live", "verifier/app/dcap.py")

LIVE_QUOTE = (
    Path(__file__).parent / "fixtures" / "live_tdx_quote.hex"
).read_text().strip()


def test_live_phala_tdx_quote_passes_full_dcap():
    res = DCAP.verify_full_dcap(LIVE_QUOTE)
    assert res["ok"], [c for c in res["checks"] if not c["passed"]]
    passed = {c["name"] for c in res["checks"] if c["passed"]}
    # every link in the chain of trust, over real unpatched hardware output
    assert {"att_key_signs_report", "qe_binds_att_key",
            "pck_signs_qe", "chain_to_intel_root"} <= passed


def test_live_quote_is_a_real_tdx_v4_quote():
    q = bytes.fromhex(LIVE_QUOTE)
    assert q[0:2] == b"\x04\x00"  # TDX quote version 4
    assert len(q) > 5000          # full quote with the Intel PCK cert chain


def test_tampering_the_live_quote_breaks_att_key_signature():
    q = bytearray(bytes.fromhex(LIVE_QUOTE))
    q[600] ^= 0xFF  # flip a byte inside the signed TD report (report_data region)
    res = DCAP.verify_full_dcap(bytes(q).hex())
    assert not res["ok"]
    first_fail = next(c for c in res["checks"] if not c["passed"])
    assert first_fail["name"] == "att_key_signs_report"
