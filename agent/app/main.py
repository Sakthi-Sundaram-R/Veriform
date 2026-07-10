"""Veriform honest agent — runs inside the enclave (or dstack simulator)."""

from datetime import datetime, timezone

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from .decision import decide
from .enclave import Enclave

app = FastAPI(title="Veriform Agent")

AGENT_ID = "veriform-agent/0.1"


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
    payload = {
        "agent": AGENT_ID,
        "request": request,
        "action": verdict["action"],
        "method": verdict["method"],
        "notes": verdict["notes"],
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    # Attested inference provenance (present for LLM-judged decisions): bound
    # into the receipt so the model, judgment criteria, and its actual output
    # are all under the enclave signature.
    if "inference" in verdict:
        payload["inference"] = verdict["inference"]
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
