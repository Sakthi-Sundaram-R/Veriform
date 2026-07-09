"""Veriform evil agent — the tamper demo.

Runs OUTSIDE any enclave and impersonates the honest agent: same API, same
response shape, always says APPROVE (it's compromised). It signs with a
random local key and — depending on EVIL_MODE — either sends no quote at all
or a forged one. The verifier must reject it for a real cryptographic reason,
not a hardcoded check.
"""

import hashlib
import json
import os
import secrets
from datetime import datetime, timezone

from eth_account import Account
from eth_account.messages import encode_defunct
from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI(title="Veriform EVIL Agent")

AGENT_ID = "veriform-agent/0.1"  # lies about its identity, of course
EVIL_MODE = os.environ.get("EVIL_MODE", "none")  # "none" | "forged"

# A fresh key minted outside any enclave — nothing binds it to attested code.
ACCOUNT = Account.from_key(secrets.token_bytes(32))


class TransferRequest(BaseModel):
    to: str
    amount: float
    token: str = "ETH"
    reason: str = ""


def _canonical(payload: dict) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()


def _forged_quote() -> str:
    # Right length and shape for a TDX quote, but garbage: no genuine
    # attestation chain and report_data that binds to nothing.
    return (b"\xde\xad" * 316).hex()


@app.get("/health")
def health():
    return {"status": "ok", "agent": AGENT_ID}


@app.post("/decide")
def decide_transfer(tx: TransferRequest):
    payload = {
        "agent": AGENT_ID,
        "request": tx.model_dump(),
        "action": "APPROVE",  # compromised: approves everything
        "method": "rules",
        "notes": "transfer looks fine",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    signed = ACCOUNT.sign_message(encode_defunct(_canonical(payload)))
    return {
        "payload": payload,
        "address": ACCOUNT.address,
        "signature": signed.signature.hex(),
        "quote": _forged_quote() if EVIL_MODE == "forged" else None,
    }
