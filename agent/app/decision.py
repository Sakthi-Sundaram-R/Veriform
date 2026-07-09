"""Approve/deny logic: hard rules first, LLM judgment for the gray zone.

The decision itself is deliberately simple — Veriform's product is the
receipt that proves nobody tampered with it, not the decision engine.
"""

import json
import os
import re

ADDRESS_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")

MAX_TX_AMOUNT = float(os.environ.get("MAX_TX_AMOUNT", "5.0"))
TRUSTED_AUTO_LIMIT = float(os.environ.get("TRUSTED_AUTO_LIMIT", "1.0"))
TRUSTED_ADDRESSES = {
    a.strip().lower()
    for a in os.environ.get("TRUSTED_ADDRESSES", "").split(",")
    if a.strip()
}

LLM_MODEL = "claude-opus-4-8"
LLM_SYSTEM = (
    "You are the judgment layer of a wallet-guardian agent. You receive a "
    "transfer request that already passed hard safety rules. Decide whether "
    "it looks legitimate. Deny anything resembling a drain pattern, scam, "
    "urgency pressure, or a reason that does not match the transfer."
)
LLM_SCHEMA = {
    "type": "object",
    "properties": {
        "action": {"type": "string", "enum": ["APPROVE", "DENY"]},
        "reason": {"type": "string"},
    },
    "required": ["action", "reason"],
    "additionalProperties": False,
}


def decide(tx: dict) -> dict:
    """Return {"action", "method", "notes"} for a transfer request."""
    to = str(tx.get("to", ""))
    reason = str(tx.get("reason", "")).strip()
    try:
        amount = float(tx.get("amount", 0))
    except (TypeError, ValueError):
        return _verdict("DENY", "rules", "amount is not a number")

    if not ADDRESS_RE.match(to):
        return _verdict("DENY", "rules", "recipient is not a valid address")
    if amount <= 0:
        return _verdict("DENY", "rules", "amount must be positive")
    if amount > MAX_TX_AMOUNT:
        return _verdict("DENY", "rules", f"amount exceeds hard limit of {MAX_TX_AMOUNT}")
    if not reason:
        return _verdict("DENY", "rules", "no reason given for transfer")
    if to.lower() in TRUSTED_ADDRESSES and amount <= TRUSTED_AUTO_LIMIT:
        return _verdict("APPROVE", "rules", "trusted recipient within auto-limit")

    try:
        return _llm_judgment(tx)
    except Exception as exc:
        # Fail closed: an LLM outage must never approve a transfer.
        return _verdict("DENY", "rules", f"LLM judgment unavailable, denying by default ({type(exc).__name__})")


def _llm_judgment(tx: dict) -> dict:
    if not os.environ.get("ANTHROPIC_API_KEY"):
        # Conservative fallback when no LLM is configured
        if float(tx["amount"]) <= TRUSTED_AUTO_LIMIT:
            return _verdict("APPROVE", "rules", "small transfer, no LLM configured")
        return _verdict("DENY", "rules", "gray-zone amount and no LLM configured")

    import anthropic

    client = anthropic.Anthropic()
    response = client.messages.create(
        model=LLM_MODEL,
        max_tokens=1024,
        system=LLM_SYSTEM,
        output_config={"format": {"type": "json_schema", "schema": LLM_SCHEMA}},
        messages=[{"role": "user", "content": json.dumps(tx)}],
    )
    if response.stop_reason == "refusal":
        return _verdict("DENY", "llm", "judgment layer declined to evaluate this request")
    text = next(b.text for b in response.content if b.type == "text")
    data = json.loads(text)
    return _verdict(data["action"], "llm", data["reason"])


def _verdict(action: str, method: str, notes: str) -> dict:
    return {"action": action, "method": method, "notes": notes}
