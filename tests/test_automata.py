"""Proves AttestedQuoteConsumer.sol's on-chain logic matches, byte for byte,
the enclave that produces quotes and the off-chain verifier that reads them.

We can't run the EVM here, but the contract does exactly two computations, and
both are pure functions we can mirror in Python and pin against ground truth:

  1. reportDataBinding(quote) = quote[568:600]
     -> must equal the report_data slice the off-chain verifier checks, on a
        REAL captured hardware quote (proves the byte offset is right on-chain).

  2. expectedBinding(decisionHash, enclave)
        = sha256(decisionHash || ascii-lowercase-hex(enclave))
     -> must equal the enclave's own report_data binding
        (proves the on-chain recomputation matches agent/app/enclave.py).

If both hold, a genuine quote that Automata's DCAP verifier accepts will also
satisfy the contract's binding check, and a quote reused for another decision
won't.
"""

import hashlib
from pathlib import Path

from conftest import load_module

ENC = load_module("veriform_enclave_auto", "agent/app/enclave.py")
VERIFY = load_module("veriform_verify_auto", "verifier/app/verify.py")

REAL_QUOTE = (
    Path(__file__).parent / "fixtures" / "real_tdx_quote.hex"
).read_text().strip()

PAYLOAD = {"action": "APPROVE", "amount": "2.0", "reason": "rent"}
ADDR = "0x52908400098527886E0F7030069857D2E4169EE7"  # mixed-case, on purpose


def sol_report_data_binding(quote_hex: str) -> bytes:
    """Mirror of reportDataBinding(): calldataload reads 32 big-endian bytes
    starting at REPORT_DATA_OFFSET (568)."""
    q = bytes.fromhex(quote_hex.removeprefix("0x"))
    off = VERIFY.REPORT_DATA_OFFSET
    return q[off:off + 32]


def sol_to_lower_hex_bytes(addr: str) -> bytes:
    """Mirror of _toLowerHexBytes(): the 42-byte '0x…' lowercase ASCII form."""
    return addr.lower().encode()


def sol_expected_binding(decision_hash: bytes, addr: str) -> bytes:
    """Mirror of expectedBinding(): sha256(decisionHash || lowerHex(addr))."""
    return hashlib.sha256(decision_hash + sol_to_lower_hex_bytes(addr)).digest()


def test_report_data_offset_matches_verifier_on_real_quote():
    # what the contract reads on-chain == what the off-chain verifier reads
    got = sol_report_data_binding(REAL_QUOTE)
    q = bytes.fromhex(REAL_QUOTE)
    off_slice = q[VERIFY.REPORT_DATA_OFFSET:VERIFY.REPORT_DATA_END][:32]
    assert got == off_slice
    assert len(got) == 32


def test_expected_binding_matches_enclave_scheme():
    # the contract's on-chain sha256 recomputation == the enclave's own binding
    decision_hash = hashlib.sha256(ENC.canonical_bytes(PAYLOAD)).digest()
    onchain = sol_expected_binding(decision_hash, ADDR)
    enclave_report_data = ENC.expected_report_data(PAYLOAD, ADDR)
    assert onchain == enclave_report_data[:32]


def test_binding_also_matches_verifier_expected_binding():
    # and the verifier's expected_binding() agrees with the on-chain value
    decision_hash = hashlib.sha256(ENC.canonical_bytes(PAYLOAD)).digest()
    onchain = sol_expected_binding(decision_hash, ADDR)
    assert onchain == VERIFY.expected_binding(PAYLOAD, ADDR)


def test_lowercase_hex_encoding_is_exact():
    # the Solidity _toLowerHexBytes must produce the identical 42 ASCII bytes
    assert sol_to_lower_hex_bytes(ADDR) == ADDR.lower().encode()
    assert len(sol_to_lower_hex_bytes(ADDR)) == 42


def test_wrong_decision_breaks_the_binding():
    decision_hash = hashlib.sha256(ENC.canonical_bytes(PAYLOAD)).digest()
    want = sol_expected_binding(decision_hash, ADDR)
    other = hashlib.sha256(ENC.canonical_bytes({**PAYLOAD, "action": "DENY"})).digest()
    got = sol_expected_binding(other, ADDR)
    assert got != want  # BindingMismatch would revert on-chain


def test_wrong_enclave_key_breaks_the_binding():
    decision_hash = hashlib.sha256(ENC.canonical_bytes(PAYLOAD)).digest()
    want = sol_expected_binding(decision_hash, ADDR)
    other = sol_expected_binding(decision_hash,
                                 "0x0000000000000000000000000000000000000001")
    assert other != want
