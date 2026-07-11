"""Multi-judge consensus: the verifier confirms the final action genuinely
followed from a quorum of independent judges — so no single rogue, hallucinating,
or backdoored judge can force an approval, and a compromised agent can't lower
its own threshold or misreport the tally.
"""

from conftest import load_module

V = load_module("veriform_verify_con", "verifier/app/verify.py")


def payload(action, votes, threshold=2):
    approvals = sum(1 for v in votes if v["action"] == "APPROVE")
    return {
        "action": action, "request": {},
        "consensus": {"threshold": threshold, "total": len(votes),
                      "approvals": approvals, "votes": votes},
    }


A = {"judge": "gemini", "action": "APPROVE", "reason": "ok"}
D = {"judge": "scam-heuristic", "action": "DENY", "reason": "scam"}
D2 = {"judge": "amount-heuristic", "action": "DENY", "reason": "too big"}


def test_quorum_met_approve_verifies():
    r = V._consensus_check(payload("APPROVE", [A, dict(A, judge="scam"), D2], threshold=2))
    assert r["passed"] is True


def test_quorum_not_met_deny_verifies():
    r = V._consensus_check(payload("DENY", [A, D, D2], threshold=2))
    assert r["passed"] is True  # 1 approval < 2, action DENY is correct


def test_single_rogue_cannot_force_approval():
    # One rogue judge approves a scam; the other two deny. A compromised agent
    # claims APPROVE anyway. The verifier rejects it: quorum wasn't met.
    rogue = {"judge": "rogue", "action": "APPROVE", "reason": "approves everything"}
    r = V._consensus_check(payload("APPROVE", [rogue, D, D2], threshold=2))
    assert r["passed"] is False
    assert "does not follow the quorum" in r["detail"]


def test_agent_misreporting_tally_rejected():
    p = payload("APPROVE", [A, D, D2], threshold=2)
    p["consensus"]["approvals"] = 3  # lie: claim everyone approved
    r = V._consensus_check(p)
    assert r["passed"] is False
    assert "approvals" in r["detail"]


def test_pinned_threshold_blocks_weakening(monkeypatch):
    # Agent lowers its own threshold to 1 so one judge decides; verifier pins 2.
    monkeypatch.setattr(V, "EXPECTED_CONSENSUS_THRESHOLD", 2)
    r = V._consensus_check(payload("APPROVE", [A, D, D2], threshold=1))
    assert r["passed"] is False
    assert "below the required" in r["detail"]


def test_non_consensus_decision_skipped():
    r = V._consensus_check({"action": "APPROVE", "request": {}})
    assert r["passed"] is None
