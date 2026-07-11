"""LOCAL DEV SHIM — NOT A TEE. NOT THE OFFICIAL SIMULATOR.

Speaks the dstack guest-agent wire protocol (POST /GetKey, /GetQuote) so the
unmodified agent container can run on platforms where `phala simulator start`
isn't available yet (e.g. Windows).

Exactly like the official Phala simulator, it serves a REAL captured TDX quote
(base_quote.hex — a genuine Intel-signed quote) and patches the caller's
report_data into it at the standard offset. So its quotes carry a real Intel
PCK certificate chain (quote_authenticity passes), the correct pinned MRTD, and
the caller's decision binding. The one thing it can't do — and honestly won't —
is re-sign the quote body over the patched report_data, so FULL DCAP
(FULL_DCAP=1) correctly fails on it. That's exactly the guarantee real hardware
adds; see docs.

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

# A real captured TDX quote (Intel-signed chain + real MRTD). report_data is the
# last 64 bytes of the TD report body: absolute offset 568..632.
BASE_QUOTE = bytes.fromhex(
    open(os.path.join(os.path.dirname(__file__), "base_quote.hex")).read().strip()
)
REPORT_DATA_OFFSET = 568
REPORT_DATA_END = 632


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
    quote = bytearray(BASE_QUOTE)
    quote[REPORT_DATA_OFFSET:REPORT_DATA_END] = report_data  # patch in, like the official sim
    event_log = json.dumps(
        [{"imr": 0, "event_type": 0, "digest": "00" * 48, "event": "dev-shim", "event_payload": ""}]
    )
    return {"quote": bytes(quote).hex(), "event_log": event_log, "report_data": report_data.hex()}
