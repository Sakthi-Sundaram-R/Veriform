"""Everything that touches the TEE lives here.

Two primitives, both via the dstack SDK:
  * a signing key derived inside the enclave (never leaves it)
  * a hardware quote whose report_data binds a specific decision to this enclave

Binding scheme (the verifier recomputes and compares this):
  canonical      = deterministic JSON of the decision payload
  decision_hash  = sha256(canonical)
  report_data    = sha256(decision_hash || lowercase_address) padded to 64 bytes
"""

import hashlib
import json

from dstack_sdk import DstackClient
from eth_account import Account
from eth_account.messages import encode_defunct


def canonical_bytes(payload: dict) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()


def expected_report_data(payload: dict, address: str) -> bytes:
    decision_hash = hashlib.sha256(canonical_bytes(payload)).digest()
    binding = hashlib.sha256(decision_hash + address.lower().encode()).digest()
    return binding + b"\x00" * 32  # report_data is 64 bytes


class Enclave:
    def __init__(self) -> None:
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

    def attest(self, payload: dict) -> dict:
        """Sign the decision and bind it to this enclave with a quote."""
        report_data = expected_report_data(payload, self.address)
        quote_resp = self._client.get_quote(report_data)
        signed = self._account.sign_message(encode_defunct(canonical_bytes(payload)))
        return {
            "address": self.address,
            "signature": signed.signature.hex(),
            "quote": quote_resp.quote,
        }
