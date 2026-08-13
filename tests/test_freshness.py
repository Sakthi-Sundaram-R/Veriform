"""Replay guard: a signed receipt is only acceptable inside a pinned age window.

The timestamp lives in the signed, quote-bound payload, so a replayer can
present an old receipt but cannot re-date it. Capping the age is therefore what
turns "valid forever" into "valid for a window".
"""

from datetime import datetime, timedelta, timezone

from conftest import load_module

V = load_module("veriform_verify_fresh", "verifier/app/verify.py")


def payload(age_seconds=0, with_timestamp=True):
    p = {"action": "APPROVE", "request": {}, "method": "rules"}
    if with_timestamp:
        ts = datetime.now(timezone.utc) - timedelta(seconds=age_seconds)
        p["timestamp"] = ts.isoformat()
    return p


def test_skipped_when_no_expiry_pinned(monkeypatch):
    monkeypatch.setattr(V, "MAX_RECEIPT_AGE_SECONDS", 0)
    r = V._freshness_check(payload(age_seconds=99999))
    assert r["passed"] is None
    assert "indefinitely" in r["detail"]


def test_fresh_receipt_passes(monkeypatch):
    monkeypatch.setattr(V, "MAX_RECEIPT_AGE_SECONDS", 300)
    r = V._freshness_check(payload(age_seconds=5))
    assert r["passed"] is True


def test_stale_receipt_rejected(monkeypatch):
    # The replay case: a genuine APPROVE captured earlier and presented again.
    monkeypatch.setattr(V, "MAX_RECEIPT_AGE_SECONDS", 300)
    r = V._freshness_check(payload(age_seconds=3600))
    assert r["passed"] is False
    assert "replayed" in r["detail"]


def test_boundary_just_inside_window(monkeypatch):
    monkeypatch.setattr(V, "MAX_RECEIPT_AGE_SECONDS", 300)
    assert V._freshness_check(payload(age_seconds=290))["passed"] is True


def test_missing_timestamp_rejected_when_pinned(monkeypatch):
    # Same rule as the other pins: dropping the field must not evade the policy.
    monkeypatch.setattr(V, "MAX_RECEIPT_AGE_SECONDS", 300)
    r = V._freshness_check(payload(with_timestamp=False))
    assert r["passed"] is False
    assert "age cannot be established" in r["detail"]


def test_malformed_timestamp_rejected(monkeypatch):
    monkeypatch.setattr(V, "MAX_RECEIPT_AGE_SECONDS", 300)
    p = payload()
    p["timestamp"] = "last tuesday"
    r = V._freshness_check(p)
    assert r["passed"] is False
    assert "ISO-8601" in r["detail"]


def test_future_dated_receipt_rejected(monkeypatch):
    # A pre-minted receipt, or a clock far enough off to be untrustworthy.
    monkeypatch.setattr(V, "MAX_RECEIPT_AGE_SECONDS", 300)
    monkeypatch.setattr(V, "FUTURE_SKEW_TOLERANCE_SECONDS", 60)
    r = V._freshness_check(payload(age_seconds=-600))
    assert r["passed"] is False
    assert "future" in r["detail"]


def test_small_clock_skew_tolerated(monkeypatch):
    monkeypatch.setattr(V, "MAX_RECEIPT_AGE_SECONDS", 300)
    monkeypatch.setattr(V, "FUTURE_SKEW_TOLERANCE_SECONDS", 60)
    assert V._freshness_check(payload(age_seconds=-10))["passed"] is True


def test_naive_timestamp_treated_as_utc(monkeypatch):
    monkeypatch.setattr(V, "MAX_RECEIPT_AGE_SECONDS", 300)
    p = payload()
    p["timestamp"] = datetime.now(timezone.utc).replace(tzinfo=None).isoformat()
    assert V._freshness_check(p)["passed"] is True


def test_history_entries_exempt_from_expiry(monkeypatch):
    """A decision history is retrospective — old entries must still verify.

    Guards the regression where pinning an expiry would make every past receipt
    in verify_sequence fail purely for being old.
    """
    monkeypatch.setattr(V, "MAX_RECEIPT_AGE_SECONDS", 1)
    old = payload(age_seconds=99999)
    names = [c["name"] for c in
             V.verify_receipt(old, "0x" + "11" * 20, "0x", None,
                              check_freshness=False)["checks"]]
    assert "freshness" not in names
    # ...and it IS applied when the same receipt is presented on its own.
    names_single = [c["name"] for c in
                    V.verify_receipt(old, "0x" + "11" * 20, "0x", None)["checks"]]
    assert "freshness" in names_single
