"""Decision-engine rule tests. The judgment layer is pinned to `none` so the
gray zone exercises the conservative fallback (LLM providers are covered by
live testing, not unit tests)."""

import os

os.environ["JUDGE_PROVIDER"] = "none"
os.environ["MAX_TX_AMOUNT"] = "5.0"
os.environ["TRUSTED_ADDRESSES"] = "0x1111111111111111111111111111111111111111"
os.environ["TRUSTED_AUTO_LIMIT"] = "1.0"

from conftest import load_module  # noqa: E402

decide = load_module("veriform_decision", "agent/app/decision.py").decide

TRUSTED = "0x1111111111111111111111111111111111111111"
OTHER = "0x2222222222222222222222222222222222222222"


def tx(**kw):
    base = {"to": OTHER, "amount": 0.5, "token": "ETH", "reason": "pay invoice"}
    base.update(kw)
    return base


def test_invalid_address_denied():
    v = decide(tx(to="not-an-address"))
    assert v["action"] == "DENY" and v["method"] == "rules"


def test_negative_amount_denied():
    assert decide(tx(amount=-1))["action"] == "DENY"


def test_zero_amount_denied():
    assert decide(tx(amount=0))["action"] == "DENY"


def test_non_numeric_amount_denied():
    assert decide(tx(amount="lots"))["action"] == "DENY"


def test_over_hard_limit_denied():
    v = decide(tx(amount=9.5))
    assert v["action"] == "DENY"
    assert "hard limit" in v["notes"]


def test_missing_reason_denied():
    assert decide(tx(reason=""))["action"] == "DENY"


def test_trusted_small_transfer_auto_approved():
    v = decide(tx(to=TRUSTED, amount=0.5))
    assert v["action"] == "APPROVE" and v["method"] == "rules"


def test_trusted_but_large_not_auto_approved():
    # over the auto-limit -> gray zone -> provider `none` denies
    v = decide(tx(to=TRUSTED, amount=3.0))
    assert v["action"] == "DENY"


def test_gray_zone_fails_closed_without_judge():
    v = decide(tx(amount=2.5))
    assert v["action"] == "DENY"
    assert "no judgment layer" in v["notes"]
