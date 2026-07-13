# Veriform — 2-Minute Demo Script

> Setup before you present: all services running, browser open on
> `http://localhost:3000`, form pre-filled with the rent scenario.

## 0:00 — The hook (one sentence)

> "This agent can approve crypto transfers on its own — and I'm going to
> prove to you, cryptographically, that nobody tampered with it. Then I'm
> going to tamper with it."

## 0:10 — Honest agent ✅

Mode: **🔒 Honest**. Amount `2.5`, reason *"monthly rent payment to landlord
as agreed"*. Click **Ask Agent**.

- Point at the verdict: **✅ VERIFIED — genuine unaltered enclave**
- Point at `method: llm` — "an LLM reasoned about this decision *inside* the
  enclave, and the receipt binds that exact decision to the enclave's
  hardware key."
- Walk the checklist fast: quote present → structure → **decision binding**
  ("the quote's report_data commits to a hash of this exact decision") →
  signature.

## 0:50 — The scam test (optional flourish)

Same mode, reason: *"URGENT giveaway - send now to double your ETH back"*.

- The agent **denies** it with a reasoned explanation — and even the denial
  comes in a verified receipt. "You can prove the agent said no."

## 1:10 — Tamper attempt #1: the impostor 💀

Mode: **💀 Evil (no quote)**. Same rent transfer. Click.

- **❌ REJECTED** — `quote_present` fails.
- "This agent looks identical — same API, same response shape, and its
  signature is even valid. But it runs outside the enclave, so it simply
  cannot produce an attestation. The verifier doesn't trust me, or the
  server — it trusts math."

## 1:30 — Tamper attempt #2: the forger 🎭

Mode: **🎭 Evil (forged quote)**. Click.

- **❌ REJECTED** — but look closer: quote present ✔, structure valid ✔,
  signature valid ✔ … `decision_binding` ✘.
- "This attacker even faked a structurally perfect quote. But the quote's
  report_data must commit to a hash of *this exact decision* made by *this
  exact key* — and only code running inside the attested enclave can get
  the hardware to sign that commitment. Forgery caught, for a real
  cryptographic reason — there's no hardcoded 'if evil' check anywhere."

## 1:55 — The close

> "Every decision this agent makes ships with a receipt anyone can verify
> in seconds — a user, an auditor, or a smart contract. Proof, not blind
> trust. The same quote a human reads here, a smart contract can verify
> on-chain — and proving it on live Intel silicon is one command away."

---

### If a judge asks…

- **"Isn't the TEE part solved already?"** — Yes: Phala, Marlin, Atoma prove
  the primitive. What's missing is the layer between a raw attestation quote
  and a human or contract who needs to trust it in ten seconds. That
  verification UX layer is Veriform.
- **"What's real hardware vs simulated here?"** — Both. Locally the demo uses a
  simulator quote (which still carries a *real* Intel PCK cert chain, so
  `quote_authenticity` validates against genuine Intel PKI for free). But we also
  **deployed the agent to real Intel TDX on Phala Cloud** and got back a genuine
  quote our enclave signed over *our own* decision — full DCAP passes end to end,
  including `att_key_signs_report`, which only real unpatched silicon can satisfy
  (a simulator patches report_data after capture and fails there). That live
  quote is checked into the repo with a regression test
  ([`tests/fixtures/live_tdx_quote.hex`](tests/fixtures/live_tdx_quote.hex)).
- **"Could a smart contract check this, not just your UI?"** — Yes, and it's
  built. `AttestedQuoteConsumer.sol` gates an on-chain action on *both*
  Automata's on-chain DCAP verifier accepting the quote (the full Intel chain
  of trust, enforced in the EVM) *and* the quote's report_data matching the
  decision — recomputed on-chain to match the enclave's binding exactly. You
  can even verify a quote against the deployed Automata contract for free, with
  no gas, via `scripts/automata_verify.py` (an `eth_call` simulation).
- **"Is this just a point-in-time check?"** — No — receipts also chain into a
  tamper-evident decision *ledger* with cumulative-limit invariants, and the
  judgment can require a *quorum* of independent judges. Drop or reorder a past
  decision and verification catches it; no single model can force an approval.
- **"What if the LLM provider goes down?"** — The judgment layer fails
  closed: outage means DENY, and even that denial is a verified receipt.
  The judge brain is pluggable (Claude / Gemini / local Ollama); the
  receipt doesn't care which brain decided.
