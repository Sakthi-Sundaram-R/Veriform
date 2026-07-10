"""Proves the on-chain anchor is signature-compatible with the enclave key.

Solidity's ecrecover on an EIP-191 digest recovers the same address that
eth_account signs with. We can't run the EVM here without a toolchain, but
we CAN prove the exact recovery Solidity performs — ecrecover(digest, v,r,s)
— yields the attested address, and yields a different address for an
outsider (the evil agent). That equivalence is the whole contract.
"""

import hashlib
import json
import secrets

from eth_account import Account
from eth_account.messages import encode_defunct
from eth_hash.auto import keccak
from eth_keys import keys


PAYLOAD = {
    "agent": "veriform-agent/0.1",
    "request": {"to": "0xabc", "amount": 0.5, "reason": "rent"},
    "action": "APPROVE",
}


def canonical_bytes(payload):
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()


def eip191_digest(message: bytes) -> bytes:
    """The 32-byte digest Solidity's ecrecover consumes for a personal_sign:
    keccak256("\\x19Ethereum Signed Message:\\n32" || keccak256(message))."""
    inner = keccak(message)
    prefix = b"\x19Ethereum Signed Message:\n32"
    return keccak(prefix + inner)


def solidity_ecrecover(digest: bytes, signature: bytes) -> str:
    """Mirror of VeriformRegistry.recover(): split {r,s,v}, recover pubkey."""
    r = int.from_bytes(signature[0:32], "big")
    s = int.from_bytes(signature[32:64], "big")
    v = signature[64]
    if v >= 27:
        v -= 27
    sig = keys.Signature(vrs=(v, r, s))
    pub = sig.recover_public_key_from_msg_hash(digest)
    return pub.to_checksum_address()


def sign_for_chain(account, payload):
    """What the enclave would do to make an on-chain-verifiable receipt:
    sign the keccak256 of the canonical payload with personal_sign."""
    inner = keccak(canonical_bytes(payload))
    signed = account.sign_message(encode_defunct(inner))
    return bytes(signed.signature)


def test_attested_signature_recovers_onchain():
    agent = Account.from_key(secrets.token_bytes(32))
    sig = sign_for_chain(agent, PAYLOAD)
    digest = eip191_digest(canonical_bytes(PAYLOAD))
    recovered = solidity_ecrecover(digest, sig)
    assert recovered.lower() == agent.address.lower()


def test_evil_signature_recovers_to_different_address():
    agent = Account.from_key(secrets.token_bytes(32))
    evil = Account.from_key(secrets.token_bytes(32))
    sig = sign_for_chain(evil, PAYLOAD)  # signed outside the enclave
    digest = eip191_digest(canonical_bytes(PAYLOAD))
    recovered = solidity_ecrecover(digest, sig)
    # Registry.isVerifiedDecision would compare this to attestedAgent (agent)
    assert recovered.lower() != agent.address.lower()
    assert recovered.lower() == evil.address.lower()


def test_tampered_digest_does_not_recover_agent():
    agent = Account.from_key(secrets.token_bytes(32))
    sig = sign_for_chain(agent, PAYLOAD)
    tampered = dict(PAYLOAD, action="DENY")
    digest = eip191_digest(canonical_bytes(tampered))
    recovered = solidity_ecrecover(digest, sig)
    assert recovered.lower() != agent.address.lower()
