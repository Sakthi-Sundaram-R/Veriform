"""Attested decision ledger: a receipt SEQUENCE is verifiable as a complete,
ordered, policy-compliant history — dropping, reordering, or tampering with any
decision is caught, and a cumulative-limit breach is caught even though every
individual transfer is under the per-tx limit.
"""

import secrets

from eth_account import Account
from eth_account.messages import encode_defunct

from conftest import load_module

V = load_module("veriform_verify_led", "verifier/app/verify.py")
LED = load_module("veriform_ledger", "agent/app/ledger.py")

# Real Intel chain so receipts pass authenticity; reuse the verify test's helper idea.
from pathlib import Path
_FIX = bytes.fromhex((Path(__file__).parent / "fixtures" / "official_sim_quote.hex").read_text().strip())
_CHAIN = _FIX[_FIX.find(b"-----BEGIN CERTIFICATE-----"):]

AGENT = Account.from_key(secrets.token_bytes(32))


def make_signed(payload):
    """Build a fully valid receipt (quote bound + signed) for a payload."""
    report_data = V.expected_binding(payload, AGENT.address) + b"\x00" * 32
    quote = bytearray(700)
    quote[V.REPORT_DATA_OFFSET:V.REPORT_DATA_END] = report_data
    quote += _CHAIN
    sig = AGENT.sign_message(encode_defunct(V.canonical_bytes(payload))).signature.hex()
    return {"payload": payload, "address": AGENT.address,
            "signature": sig, "quote": bytes(quote).hex()}


def build_history(amounts, actions, day="2026-07-10", limit=5.0):
    """Simulate the agent's ledger producing a sequence of signed receipts."""
    ledger = LED.DecisionLedger(limit)
    receipts = []
    for amt, act in zip(amounts, actions):
        payload = {
            "agent": "veriform-agent/0.1",
            "request": {"to": "0x" + "1" * 40, "amount": amt, "token": "ETH", "reason": "x"},
            "action": act,
            "method": "rules",
            "notes": "n",
            "timestamp": f"{day}T00:00:00+00:00",
        }
        import datetime as _dt
        now = _dt.datetime.fromisoformat(f"{day}T00:00:00+00:00")
        payload["ledger"] = ledger.append(payload, amt, act, now=now)
        receipts.append(make_signed(payload))
    return receipts


def test_clean_history_verifies():
    r = build_history([1.0, 1.0, 1.0], ["APPROVE", "APPROVE", "DENY"])
    res = V.verify_sequence(r)
    assert res["verified"], res


def test_dropped_decision_detected():
    r = build_history([1.0, 1.0, 1.0], ["APPROVE", "APPROVE", "APPROVE"])
    del r[1]  # silently drop the middle decision
    res = V.verify_sequence(r)
    assert not res["verified"]
    assert any("dropped" in f or "chain" in f for f in res["findings"])


def test_reordered_decisions_detected():
    r = build_history([1.0, 2.0, 1.0], ["APPROVE", "APPROVE", "DENY"])
    r[0], r[1] = r[1], r[0]  # swap order
    res = V.verify_sequence(r)
    assert not res["verified"]


def test_tampered_decision_detected():
    r = build_history([1.0, 1.0], ["DENY", "DENY"])
    # flip a DENY to APPROVE in the stored receipt without re-signing
    r[0]["payload"]["action"] = "APPROVE"
    res = V.verify_sequence(r)
    assert not res["verified"]


def test_single_link_check_in_receipt():
    r = build_history([1.0], ["APPROVE"])
    chk = V._ledger_check(r[0]["payload"])
    assert chk["passed"] is True


def test_cumulative_limit_enforced_by_agent():
    # Each transfer is 2.0 (under a 3.0 per-tx limit), but the daily cap is 5.0.
    # The 3rd APPROVE would push the total to 6.0 -> the agent must deny it.
    ledger = LED.DecisionLedger(daily_limit=5.0)
    import datetime as _dt
    now = _dt.datetime(2026, 7, 10, tzinfo=_dt.timezone.utc)
    assert not ledger.would_breach(2.0, "APPROVE", now)  # 0 -> 2
    ledger.append({"i": 1}, 2.0, "APPROVE", now)
    assert not ledger.would_breach(2.0, "APPROVE", now)  # 2 -> 4
    ledger.append({"i": 2}, 2.0, "APPROVE", now)
    assert ledger.would_breach(2.0, "APPROVE", now)       # 4 -> 6 > 5: breach


def test_cumulative_breach_detected_in_sequence():
    # Each transfer under the per-tx limit, but three APPROVEs sum to 6.0 > 5.0.
    # The honest ledger records daily_total 2,4,6 -> the 3rd receipt claims 6.0,
    # which the per-receipt ledger check rejects.
    r = build_history([2.0, 2.0, 2.0], ["APPROVE", "APPROVE", "APPROVE"], limit=5.0)
    res = V.verify_sequence(r)
    assert not res["verified"]
    assert any("#3" in f for f in res["findings"])


def test_lying_accumulator_detected():
    # A dishonest agent hides the breach by misreporting daily_total (resets it
    # so each receipt looks under-limit). verify_sequence recomputes the running
    # total independently and catches the inconsistency.
    r = build_history([2.0, 2.0, 2.0], ["APPROVE", "APPROVE", "APPROVE"], limit=5.0)
    for item in r:
        item["payload"]["ledger"]["daily_total"] = 2.0  # lie: pretend never accumulates
        # re-sign so signature/binding still pass — only the accumulator lies
        p = item["payload"]
        item["signature"] = AGENT.sign_message(
            encode_defunct(V.canonical_bytes(p))).signature.hex()
        rd = V.expected_binding(p, AGENT.address) + b"\x00" * 32
        q = bytearray(700); q[V.REPORT_DATA_OFFSET:V.REPORT_DATA_END] = rd; q += _CHAIN
        item["quote"] = bytes(q).hex()
    res = V.verify_sequence(r)
    assert not res["verified"]
    assert any("recomputed" in f for f in res["findings"])
