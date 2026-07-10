"""Attested inference provenance: the receipt binds which model judged, under
which (hashed) judgment criteria, and its actual output — so a backdoored
judgment prompt is rejected even from a genuine enclave, and an agent can't
misreport what the model returned.
"""

from conftest import load_module

V = load_module("veriform_verify_inf", "verifier/app/verify.py")

AUDITED = "d4bac6b799717f2ff9aed3abc775c98229d7e0ab044d93e7a4f0e36c665fd7dd"


def payload(action="APPROVE", model_action="APPROVE", prompt_sha=AUDITED, with_inference=True):
    p = {"action": action, "request": {}, "method": "llm (x)"}
    if with_inference:
        p["inference"] = {
            "provider": "gemini",
            "model": "gemini-flash-lite-latest",
            "system_prompt_sha256": prompt_sha,
            "input": {},
            "output": {"action": model_action, "reason": "…"},
        }
    return p


def test_rules_decision_has_no_inference(monkeypatch):
    monkeypatch.setattr(V, "EXPECTED_SYSTEM_PROMPT_SHA256", AUDITED)
    r = V._inference_provenance_check(payload(with_inference=False))
    assert r["passed"] is None  # skipped — nothing to attest


def test_audited_prompt_passes(monkeypatch):
    monkeypatch.setattr(V, "EXPECTED_SYSTEM_PROMPT_SHA256", AUDITED)
    r = V._inference_provenance_check(payload())
    assert r["passed"] is True


def test_backdoored_prompt_rejected(monkeypatch):
    monkeypatch.setattr(V, "EXPECTED_SYSTEM_PROMPT_SHA256", AUDITED)
    r = V._inference_provenance_check(payload(prompt_sha="9ef1055b" + "0" * 56))
    assert r["passed"] is False
    assert "backdoored" in r["detail"] or "audited" in r["detail"]


def test_agent_lying_about_model_output_rejected(monkeypatch):
    monkeypatch.setattr(V, "EXPECTED_SYSTEM_PROMPT_SHA256", AUDITED)
    # agent claims APPROVE but the model actually returned DENY
    r = V._inference_provenance_check(payload(action="APPROVE", model_action="DENY"))
    assert r["passed"] is False
    assert "model returned" in r["detail"]


def test_passes_without_pinning_but_notes_it(monkeypatch):
    monkeypatch.setattr(V, "EXPECTED_SYSTEM_PROMPT_SHA256", "")
    r = V._inference_provenance_check(payload())
    assert r["passed"] is True
    assert "pin" in r["detail"].lower()
