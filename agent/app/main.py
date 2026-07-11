"""Veriform honest agent — runs inside the enclave (or dstack simulator)."""

import os
from datetime import datetime, timezone

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from .decision import MAX_TX_AMOUNT, decide
from .enclave import Enclave
from .ledger import DecisionLedger

app = FastAPI(title="Veriform Agent")

AGENT_ID = "veriform-agent/0.1"

# Cumulative daily approval cap — a cross-decision policy no per-transfer check
# can enforce. Defaults to a small multiple of the per-tx hard limit.
DAILY_LIMIT = float(os.environ.get("DAILY_LIMIT", MAX_TX_AMOUNT * 2))
LEDGER = DecisionLedger(DAILY_LIMIT)


class TransferRequest(BaseModel):
    to: str
    amount: float
    token: str = "ETH"
    reason: str = ""


@app.get("/health")
def health():
    return {"status": "ok", "agent": AGENT_ID}


@app.post("/decide")
def decide_transfer(tx: TransferRequest):
    request = tx.model_dump()
    verdict = decide(request)
    action, method, notes = verdict["action"], verdict["method"], verdict["notes"]
    inference = verdict.get("inference")
    consensus = verdict.get("consensus")

    # Cross-decision policy invariant: even if each transfer passes on its own,
    # a genuine APPROVE is overridden to DENY if it would breach the cumulative
    # daily limit. This is a rules-level override, so it supersedes the judges.
    amount = float(request.get("amount", 0) or 0)
    if action == "APPROVE" and LEDGER.would_breach(amount, action):
        action, method, inference, consensus = "DENY", "rules", None, None
        notes = f"cumulative daily limit of {DAILY_LIMIT} would be exceeded"

    payload = {
        "agent": AGENT_ID,
        "request": request,
        "action": action,
        "method": method,
        "notes": notes,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    # Attested inference provenance (present for LLM-judged decisions): bound
    # into the receipt so the model, judgment criteria, and its actual output
    # are all under the enclave signature.
    if inference is not None:
        payload["inference"] = inference
    # Multi-judge consensus: bind every vote so a verifier can confirm the final
    # action genuinely followed from a quorum (no single rogue judge decided it).
    if consensus is not None:
        payload["consensus"] = consensus

    # Append to the attested decision ledger and bind the ledger block into the
    # payload (so the whole history is quote-bound and verifiable as a chain).
    payload["ledger"] = LEDGER.append(payload, amount, action)
    try:
        receipt = Enclave().attest(payload)
    except Exception as exc:
        raise HTTPException(
            status_code=503,
            detail=(
                "Enclave unavailable — start the dstack simulator "
                f"(phala simulator start) or deploy to Phala Cloud. ({exc})"
            ),
        )
    return {"payload": payload, **receipt}
