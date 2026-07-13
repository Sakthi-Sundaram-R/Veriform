"""Self-test for the generic TDX quote backend (QUOTE_BACKEND=tsm).

We cannot run real TDX silicon in CI, so we stub the kernel's configfs entry
(the one thing hardware provides) and prove the rest of the pipeline is correct:
  * report_data is written to inblob exactly as the enclave computed it,
  * the quote read from outblob is returned unchanged (as hex),
  * that quote passes the full DCAP verifier end to end (agent -> verifier).

The stubbed outblob is the SAME real captured hardware quote the DCAP tests use,
so a green run here means: the moment this runs on an actual TDX VM, the only
thing that changes is the kernel filling outblob from our real report_data.
"""

from pathlib import Path

import pytest

from conftest import load_module

ENC = load_module("veriform_enclave", "agent/app/enclave.py")
DCAP = load_module("veriform_dcap_tsm", "verifier/app/dcap.py")

REAL_QUOTE = (
    Path(__file__).parent / "fixtures" / "real_tdx_quote.hex"
).read_text().strip()


def _stub_configfs(monkeypatch, tmp_path):
    """Replace _tsm_new_entry with one that seeds outblob like the kernel would.
    Returns the entry path so the test can inspect what got written to inblob.
    """
    entry = tmp_path / "veriform-stub"

    def fake_new_entry(base_dir):
        entry.mkdir()
        (entry / "outblob").write_bytes(bytes.fromhex(REAL_QUOTE))
        return str(entry)

    monkeypatch.setattr(ENC, "_tsm_new_entry", fake_new_entry)
    return entry


def test_tsm_writes_report_data_and_returns_quote(monkeypatch, tmp_path):
    entry = _stub_configfs(monkeypatch, tmp_path)
    report_data = b"\x11" * 64

    quote_hex = ENC.tsm_get_quote(report_data)

    # the quote came straight from outblob, unmodified
    assert quote_hex == bytes.fromhex(REAL_QUOTE).hex()
    # our exact report_data reached the kernel via inblob
    assert (entry / "inblob").read_bytes() == report_data


def test_tsm_quote_passes_full_dcap(monkeypatch, tmp_path):
    """The end-to-end payoff: a quote fetched through the tsm backend verifies
    against the real chain of trust with no verifier changes."""
    _stub_configfs(monkeypatch, tmp_path)

    quote_hex = ENC.tsm_get_quote(b"\x22" * 64)
    res = DCAP.verify_full_dcap(quote_hex)

    assert res["ok"], [c for c in res["checks"] if not c["passed"]]
    names = {c["name"] for c in res["checks"] if c["passed"]}
    assert {"att_key_signs_report", "qe_binds_att_key",
            "pck_signs_qe", "chain_to_intel_root"} <= names


def test_tsm_rejects_wrong_report_data_length():
    with pytest.raises(ValueError):
        ENC.tsm_get_quote(b"\x00" * 32)  # must be exactly 64 bytes


def test_tsm_errors_clearly_without_hardware(tmp_path):
    """Off a TDX VM the interface directory is absent — fail with guidance,
    not a bare FileNotFoundError."""
    missing = tmp_path / "no-such-tsm"
    with pytest.raises(RuntimeError, match="TDX"):
        ENC.tsm_get_quote(b"\x00" * 64, base_dir=str(missing))


def test_backend_selection_defaults_to_dstack(monkeypatch):
    monkeypatch.delenv("QUOTE_BACKEND", raising=False)
    assert ENC.resolve_quote_backend() == "dstack"
    monkeypatch.setenv("QUOTE_BACKEND", "TSM")  # case-insensitive
    assert ENC.resolve_quote_backend() == "tsm"
