"""Veriform verifier — asks an agent for a decision, verifies the receipt,
and serves the demo UI. Runs OUTSIDE the enclave: it trusts nothing but math.
"""

import os

import httpx
from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel

from .verify import verify_receipt

app = FastAPI(title="Veriform Verifier")

_AGENT_URL = os.environ.get("AGENT_URL", "http://localhost:8001")
_EVIL_URL = os.environ.get("EVIL_AGENT_URL", "http://localhost:8002")
_BACKDOORED_URL = os.environ.get("BACKDOORED_AGENT_URL", "http://localhost:8003")

# agent name -> (base_url, query params forwarded to the agent)
AGENT_TARGETS = {
    "honest": (_AGENT_URL, {}),
    "evil": (_EVIL_URL, {}),
    "evil-forged": (_EVIL_URL, {"mode": "forged"}),
    # A GENUINE enclave (valid quote + signature) whose LLM judgment prompt
    # was swapped for a backdoored one — caught by inference_provenance.
    "backdoored": (_BACKDOORED_URL, {}),
}

STATIC_DIR = os.path.join(os.path.dirname(__file__), "..", "static")


class AskRequest(BaseModel):
    agent: str  # "honest" | "evil"
    to: str
    amount: float
    token: str = "ETH"
    reason: str = ""


@app.get("/")
def index():
    return FileResponse(os.path.join(STATIC_DIR, "index.html"))


@app.post("/ask")
def ask(req: AskRequest):
    target = AGENT_TARGETS.get(req.agent)
    if not target:
        raise HTTPException(status_code=400, detail=f"unknown agent '{req.agent}'")
    base_url, params = target

    tx = {"to": req.to, "amount": req.amount, "token": req.token, "reason": req.reason}
    try:
        resp = httpx.post(f"{base_url}/decide", json=tx, params=params, timeout=120)
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=502, detail=f"agent unreachable: {exc}")
    if resp.status_code != 200:
        raise HTTPException(status_code=502, detail=f"agent error: {resp.text[:300]}")

    receipt = resp.json()
    verification = verify_receipt(
        payload=receipt.get("payload", {}),
        address=receipt.get("address", ""),
        signature=receipt.get("signature", ""),
        quote=receipt.get("quote"),
    )
    return {"agent": req.agent, "receipt": receipt, "verification": verification}
