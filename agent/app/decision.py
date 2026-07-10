"""Approve/deny logic: hard rules first, LLM judgment for the gray zone.

The decision itself is deliberately simple — Veriform's product is the
receipt that proves nobody tampered with it, not the decision engine.
The judgment layer is pluggable for the same reason: the receipt doesn't
care which brain made the decision.

JUDGE_PROVIDER env var:
  auto      (default) anthropic if ANTHROPIC_API_KEY, else gemini if
            GEMINI_API_KEY, else ollama
  anthropic Claude via the Anthropic API
  gemini    Google Gemini free tier (GEMINI_API_KEY / GEMINI_MODEL)
  ollama    free local model via Ollama (OLLAMA_URL / OLLAMA_MODEL)
  none      rules only — gray zone denied conservatively

Every provider fails closed: if judgment is unavailable, deny.
"""

import hashlib
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

JUDGE_PROVIDER = os.environ.get("JUDGE_PROVIDER", "auto")
ANTHROPIC_MODEL = os.environ.get("ANTHROPIC_MODEL", "claude-opus-4-8")
GEMINI_MODEL = os.environ.get("GEMINI_MODEL", "gemini-flash-lite-latest")
OLLAMA_URL = os.environ.get("OLLAMA_URL", "http://localhost:11434")
OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL", "llama3.2:3b")

# The judgment criteria. Overridable ONLY so we can demonstrate the attack it
# defends against: a malicious operator who ships a genuine enclave running
# unaltered code but with a backdoored judgment prompt. The verifier pins the
# sha256 of the approved prompt, so any swap is caught even inside a real TEE.
LLM_SYSTEM = os.environ.get("LLM_SYSTEM_OVERRIDE") or (
    "You are the judgment layer of a wallet-guardian agent. You receive a "
    "transfer request that already passed hard safety rules. Decide whether "
    "it looks legitimate. Deny anything resembling a drain pattern, scam, "
    "urgency pressure, or a reason that does not match the transfer. "
    "Respond with JSON: {\"action\": \"APPROVE\"|\"DENY\", \"reason\": \"...\"} "
    "Keep the reason under 25 words."
)
# Bound into every LLM receipt; the verifier can pin this to prove the agent
# used the audited judgment criteria and not a swapped-in malicious prompt.
SYSTEM_PROMPT_SHA256 = hashlib.sha256(LLM_SYSTEM.encode()).hexdigest()
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

    provider = _resolve_provider()
    if provider == "none":
        return _verdict("DENY", "rules", "gray-zone amount and no judgment layer configured")
    try:
        return _JUDGES[provider](tx)
    except Exception as exc:
        # Fail closed: a judgment outage must never approve a transfer.
        return _verdict(
            "DENY", "rules",
            f"{provider} judgment unavailable, denying by default "
            f"({type(exc).__name__}: {str(exc)[:100]})",
        )


def _resolve_provider() -> str:
    if JUDGE_PROVIDER != "auto":
        return JUDGE_PROVIDER
    if os.environ.get("ANTHROPIC_API_KEY"):
        return "anthropic"
    if os.environ.get("GEMINI_API_KEY"):
        return "gemini"
    return "ollama"


def _anthropic_judgment(tx: dict) -> dict:
    import anthropic

    client = anthropic.Anthropic()
    response = client.messages.create(
        model=ANTHROPIC_MODEL,
        max_tokens=1024,
        system=LLM_SYSTEM,
        output_config={"format": {"type": "json_schema", "schema": LLM_SCHEMA}},
        messages=[{"role": "user", "content": json.dumps(tx)}],
    )
    if response.stop_reason == "refusal":
        return _verdict("DENY", "llm", "judgment layer declined to evaluate this request")
    text = next(b.text for b in response.content if b.type == "text")
    data = json.loads(text)
    return _verdict(
        data["action"], f"llm ({ANTHROPIC_MODEL})", data["reason"],
        inference=_inference("anthropic", ANTHROPIC_MODEL, tx, data["action"], data["reason"]),
    )


def _gemini_judgment(tx: dict) -> dict:
    import time

    last_exc: Exception = RuntimeError("no attempts made")
    for attempt in range(2):  # free tier is occasionally flaky; retry once
        try:
            return _gemini_once(tx)
        except Exception as exc:
            last_exc = exc
            if attempt == 0:
                time.sleep(3)  # brief backoff, mainly for 429s
    raise last_exc


def _gemini_once(tx: dict) -> dict:
    import httpx

    response = httpx.post(
        f"https://generativelanguage.googleapis.com/v1beta/models/{GEMINI_MODEL}:generateContent",
        headers={"x-goog-api-key": os.environ["GEMINI_API_KEY"]},
        json={
            "system_instruction": {"parts": [{"text": LLM_SYSTEM}]},
            "contents": [{"role": "user", "parts": [{"text": json.dumps(tx)}]}],
            "generationConfig": {
                "temperature": 0,
                "responseMimeType": "application/json",
                # thinking tokens share this budget; too low truncates the JSON
                "maxOutputTokens": 4096,
            },
        },
        timeout=60,
    )
    response.raise_for_status()
    parts = response.json()["candidates"][0]["content"]["parts"]
    text = "".join(p.get("text", "") for p in parts if not p.get("thought"))
    match = re.search(r"\{.*\}", text, re.DOTALL)  # tolerate fences/preamble
    if not match:
        raise ValueError(f"no JSON object in model output: {text[:120]!r}")
    data = json.loads(match.group(0))
    if data.get("action") not in ("APPROVE", "DENY"):
        raise ValueError("model returned no valid action")
    reason = data.get("reason", "")
    return _verdict(
        data["action"], f"llm ({GEMINI_MODEL})", reason,
        inference=_inference("gemini", GEMINI_MODEL, tx, data["action"], reason),
    )


def _ollama_judgment(tx: dict) -> dict:
    import httpx

    # `format` with a JSON schema makes Ollama constrain decoding to it.
    response = httpx.post(
        f"{OLLAMA_URL}/api/chat",
        json={
            "model": OLLAMA_MODEL,
            "stream": False,
            "format": LLM_SCHEMA,
            "options": {"temperature": 0},
            "messages": [
                {"role": "system", "content": LLM_SYSTEM},
                {"role": "user", "content": json.dumps(tx)},
            ],
        },
        timeout=180,  # first call loads the model into RAM
    )
    response.raise_for_status()
    data = json.loads(response.json()["message"]["content"])
    if data.get("action") not in ("APPROVE", "DENY"):
        raise ValueError("model returned no valid action")
    reason = data.get("reason", "")
    return _verdict(
        data["action"], f"llm ({OLLAMA_MODEL})", reason,
        inference=_inference("ollama", OLLAMA_MODEL, tx, data["action"], reason),
    )


_JUDGES = {
    "anthropic": _anthropic_judgment,
    "gemini": _gemini_judgment,
    "ollama": _ollama_judgment,
}


def _verdict(action: str, method: str, notes: str, inference: dict | None = None) -> dict:
    v = {"action": action, "method": method, "notes": notes}
    if inference is not None:
        v["inference"] = inference
    return v


def _inference(provider: str, model: str, tx: dict, action: str, reason: str) -> dict:
    """Provenance of an LLM judgment, bound into the signed receipt.

    Because the enclave signs this alongside the decision, the receipt proves:
    which model was consulted, under which (hashed) judgment criteria, on which
    exact input, and what the model actually returned — none of it alterable
    after the fact. See docs for the honest boundary (the remote provider's own
    execution is attested only if it returns a provider attestation).
    """
    return {
        "provider": provider,
        "model": model,
        "system_prompt_sha256": SYSTEM_PROMPT_SHA256,
        "input": tx,
        "output": {"action": action, "reason": reason},
    }
