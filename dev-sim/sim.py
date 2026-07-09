"""LOCAL DEV SHIM — NOT A TEE. NOT THE OFFICIAL SIMULATOR.

Speaks the dstack guest-agent wire protocol (POST /GetKey, /GetQuote) so the
unmodified agent container can run on platforms where `phala simulator start`
isn't available yet (e.g. Windows). Like the official simulator, the "quotes"
it emits are structurally valid TDX quotes with the caller's report_data at
the right offset — but carry no hardware attestation chain. The verifier
reports quote_authenticity as skipped in this mode.

Run:  uvicorn sim:app --port 8090
Then: DSTACK_SIMULATOR_ENDPOINT=http://localhost:8090
"""

import hashlib
import json
import os

from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI(title="dstack dev shim (NOT a TEE)")

# Deterministic per-machine seed so the agent keeps the same key across restarts.
SEED = os.environ.get("SIM_SEED", "veriform-dev-shim").encode()

# TDX quote v4 layout: 48-byte header + 584-byte TD report body,
# report_data = last 64 bytes of the body (absolute offset 568..632).
HEADER = b"DSTACK-DEV-SHIM:NOT-A-REAL-QUOTE".ljust(48, b"\x00")
BODY_BEFORE_REPORT_DATA = 520


class GetKeyRequest(BaseModel):
    path: str = ""
    purpose: str = ""
    algorithm: str = "secp256k1"


class GetQuoteRequest(BaseModel):
    report_data: str  # hex


@app.post("/GetKey")
def get_key(req: GetKeyRequest):
    key = hashlib.sha256(SEED + req.path.encode() + b"|" + req.purpose.encode()).digest()
    return {"key": key.hex(), "signature_chain": []}


@app.post("/GetQuote")
def get_quote(req: GetQuoteRequest):
    report_data = bytes.fromhex(req.report_data).ljust(64, b"\x00")[:64]
    quote = HEADER + b"\x00" * BODY_BEFORE_REPORT_DATA + report_data
    event_log = json.dumps(
        [{"imr": 0, "event_type": 0, "digest": "00" * 48, "event": "dev-shim", "event_payload": ""}]
    )
    return {"quote": quote.hex(), "event_log": event_log, "report_data": report_data.hex()}
