"""Everything that touches the TEE lives here.

Two primitives:
  * a signing key derived inside the enclave (never leaves it)
  * a hardware quote whose report_data binds a specific decision to this enclave

Binding scheme (the verifier recomputes and compares this):
  canonical      = deterministic JSON of the decision payload
  decision_hash  = sha256(canonical)
  report_data    = sha256(decision_hash || lowercase_address) padded to 64 bytes

Quote backends (select with QUOTE_BACKEND):
  * "dstack" (default) — the Phala dstack SDK / local simulator. Needs
    /var/run/dstack.sock (or DSTACK_SIMULATOR_ENDPOINT).
  * "tsm" — the generic Linux TDX interface at /sys/kernel/config/tsm/report.
    Works on ANY Intel TDX VM (GCP c3, Azure DCesv6, ...) with a kernel >= 6.7
    and no dstack at all. This is the path that produces a REAL, unpatched quote
    over our own report_data — the one thing a simulator cannot give us, and the
    byte that finally makes the verifier's att_key_signs_report check pass on our
    own decision.
"""

import hashlib
import json
import os
import secrets

from eth_account import Account
from eth_account.messages import encode_defunct

TSM_REPORT_DIR = "/sys/kernel/config/tsm/report"


def canonical_bytes(payload: dict) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()


def expected_report_data(payload: dict, address: str) -> bytes:
    decision_hash = hashlib.sha256(canonical_bytes(payload)).digest()
    binding = hashlib.sha256(decision_hash + address.lower().encode()).digest()
    return binding + b"\x00" * 32  # report_data is 64 bytes


def resolve_quote_backend() -> str:
    return os.getenv("QUOTE_BACKEND", "dstack").lower()


def _tsm_new_entry(base_dir: str) -> str:
    """Create a fresh report entry directory. On configfs, mkdir triggers the
    kernel to materialise the inblob/outblob attribute files.

    Split out so it can be stubbed in tests that have no TDX hardware.
    """
    if not os.path.isdir(base_dir):
        raise RuntimeError(
            f"no TDX TSM report interface at {base_dir} — this needs a real "
            "Intel TDX VM with a kernel >= 6.7. Off hardware, use "
            "QUOTE_BACKEND=dstack (the simulator)."
        )
    entry = os.path.join(base_dir, f"veriform-{secrets.token_hex(4)}")
    os.mkdir(entry)
    return entry


def tsm_get_quote(report_data: bytes, base_dir: str = TSM_REPORT_DIR) -> str:
    """Generate a raw TDX quote over ``report_data`` via the kernel TSM
    configfs. Returns the quote as a hex string (same shape as the dstack path).

    Protocol: write the 64-byte report_data to ``inblob``, read the finished
    quote back from ``outblob``, then remove the entry.
    """
    if len(report_data) != 64:
        raise ValueError(f"report_data must be 64 bytes, got {len(report_data)}")

    entry = _tsm_new_entry(base_dir)
    try:
        with open(os.path.join(entry, "inblob"), "wb") as f:
            f.write(report_data)
        with open(os.path.join(entry, "outblob"), "rb") as f:
            quote = f.read()
    finally:
        # On configfs rmdir removes the entry even though inblob/outblob exist;
        # off configfs (tests) it may fail on a non-empty dir — best effort.
        try:
            os.rmdir(entry)
        except OSError:
            pass

    if not quote:
        raise RuntimeError("TSM report returned an empty quote")
    return quote.hex()


class Enclave:
    def __init__(self) -> None:
        from dstack_sdk import DstackClient

        self._client = DstackClient()
        self._account = self._derive_account()

    def _derive_account(self) -> Account:
        resp = self._client.get_key("veriform/signing")
        try:
            from dstack_sdk.ethereum import to_account

            return to_account(resp)
        except Exception:
            key_hex = resp.key.removeprefix("0x")
            return Account.from_key(bytes.fromhex(key_hex)[:32])

    @property
    def address(self) -> str:
        return self._account.address

    def _get_quote(self, report_data: bytes) -> str:
        if resolve_quote_backend() == "tsm":
            return tsm_get_quote(report_data)
        return self._client.get_quote(report_data).quote

    def attest(self, payload: dict) -> dict:
        """Sign the decision and bind it to this enclave with a quote."""
        report_data = expected_report_data(payload, self.address)
        quote = self._get_quote(report_data)
        signed = self._account.sign_message(encode_defunct(canonical_bytes(payload)))
        return {
            "address": self.address,
            "signature": signed.signature.hex(),
            "quote": quote,
        }
