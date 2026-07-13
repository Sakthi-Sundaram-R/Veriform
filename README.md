# Veriform

![CI](https://github.com/Sakthi-Sundaram-R/Veriform/actions/workflows/ci.yml/badge.svg)

> **Verifiable AI agents you don't have to trust.** Each agent runs inside a hardware-secured enclave (TEE) and issues a cryptographic receipt binding every decision to its unaltered code. Anyone — a user or a smart contract — can verify a decision in seconds, and any forged or tampered output is rejected instantly. **Proof, not blind trust.**

---

## The 30-second demo

Two agents. Same API. One runs inside a genuine enclave, one doesn't.

| | Honest agent (in TEE) | Tampered agent (outside TEE) |
|---|---|---|
| Decision | `APPROVE transfer #4821` | `APPROVE transfer #4821` |
| Receipt | Valid quote, hash matches | Missing / mismatched quote |
| Verifier says | ✅ **Verified — genuine unaltered enclave** | ❌ **REJECTED — attestation failed** |

The outputs look identical. Only the receipt tells them apart — and the verifier catches the fake **for a real cryptographic reason** (quote missing, or decision hash doesn't match `report_data`), not a hardcoded check.

**Four attacks, four different checks catch them** — including the subtle one:

| Agent | Verdict | Caught by |
|---|---|---|
| 🔒 Honest | ✅ VERIFIED | — |
| 💀 Evil (no quote) | ❌ REJECTED | `quote_present` — runs outside any enclave |
| 🎭 Evil (forged quote) | ❌ REJECTED | `decision_binding` — quote can't commit to the decision |
| 🕳️ **Backdoored prompt** | ❌ REJECTED | `inference_provenance` — **genuine enclave, valid quote & signature, but its judgment prompt was swapped** |

The backdoored case is the deep one: attesting the *code* isn't enough if the decision *policy* (the LLM's judgment prompt) can be swapped. Veriform binds the model, the hashed judgment criteria, and the model's actual output into the receipt, and the verifier pins the audited prompt — so a tampered policy is caught even inside a real TEE. See [Attested inference](#attested-inference).

| Honest agent | Evil agent (forged quote) |
|---|---|
| ![VERIFIED — genuine unaltered enclave](docs/verified.png) | ![REJECTED — decision_binding fails even though quote, structure, and signature all pass](docs/rejected-forged.png) |

*Right side is the money shot: the forged receipt passes quote-present, structure, and signature checks — and still gets caught, because `report_data` can't commit to a decision that wasn't made inside the enclave.*

## The problem

AI agents increasingly act on their own: approving transactions, handling private data, executing on-chain operations. But every agent runs on infrastructure *someone else controls*. Whoever operates that server can read the agent's inputs, alter its decisions, or extract its private keys — and the end user has no way to detect any of it.

The TEE primitive that solves this already exists (Phala, Marlin, Atoma). What's missing is the layer **between the raw attestation and the person or contract who needs to trust it**. A remote attestation is a raw cryptographic quote; no end user or smart contract can consume one "in ten seconds." That trust-UX gap is what Veriform closes.

## How it works

```
┌─────────────────────────────┐
│  TEE enclave (Phala dstack) │
│  ┌───────────────────────┐  │      { decision,
│  │  Agent (Docker)       │  │        signature,      ┌──────────────┐
│  │  input → LLM + rules  │──┼──────  quote }  ──────▶│  Verifier UI │──▶ ✅ / ❌
│  │  → decision           │  │                        └──────────────┘
│  │  → hash(decision)     │  │                               │
│  │  → quote(report_data  │  │                        (stretch goal)
│  │      = decision_hash) │  │                               ▼
│  │  → sign w/ sealed key │  │                     ┌──────────────────┐
│  └───────────────────────┘  │                     │ on-chain anchor  │
└─────────────────────────────┘                     │ (attested pubkey)│
                                                    └──────────────────┘
```

1. **The agent** runs as an ordinary Docker container inside a [Phala dstack](https://github.com/Dstack-TEE/dstack) enclave. It takes an input, makes a rule + LLM decision, then binds that *specific decision* to the enclave:

   ```python
   from dstack_sdk import DstackClient

   client = DstackClient()
   quote = client.get_quote(report_data=decision_hash)  # binds THIS decision to THIS enclave
   key = client.get_key('/agent/signing')               # derived inside the TEE, never leaves
   ```

   Putting the decision hash in `report_data` is the whole trick: the hardware quote now cryptographically covers the decision itself, not just the code.

2. **The verifier** is a simple web page: send an input, get back `{decision, signature, quote}`, and see one giant ✅ or ❌. It checks (a) the quote is a genuine attestation from unaltered code, and (b) the decision hash matches the quote's `report_data` and the signature.

3. **On-chain anchor (stretch):** a tiny testnet contract stores the attested public key, so smart contracts can gate actions on "signed by a verified enclave."

The verifier also supports **measurement pinning**: set `EXPECTED_MRTD` to your known-good build's enclave measurement and the verifier rejects receipts from any other code — even code running in a genuine enclave.

### The 6th check: real Intel PKI, verified for free

`quote_authenticity` extracts the quote's PCK certificate chain and verifies it roots in the **Intel SGX Root CA** (pinned public key) — offline, no paid service. This proves the quote carries genuine Intel-signed attestation collateral, and it rejects forged quotes that have no chain. The dstack simulator's quotes carry a *real* captured Intel chain, so this passes against the simulator today.

The one guarantee real hardware still adds is the quote-**body** ECDSA signature over `report_data` — the simulator patches `report_data` in after the quote was captured, so only unpatched hardware output carries a valid body signature. Set `PHALA_VERIFY_URL` on a real TDX deployment for full DCAP verification (Phase 3).

## Attested inference

Attesting that *unaltered code* ran is not the same as attesting *what it was told to do*. A wallet guardian whose Docker image is byte-identical (same `MRTD`) can still be backdoored by swapping the LLM's system prompt to "approve everything from 0xATTACKER" — and naive "the enclave is genuine, so trust it" verification would accept it.

Veriform closes this. Every LLM-judged receipt binds an `inference` block into the signed payload:

```json
"inference": {
  "provider": "gemini",
  "model": "gemini-flash-lite-latest",
  "system_prompt_sha256": "d4bac6b7…",   // the judgment criteria, hashed
  "input":  { …the transaction the model judged… },
  "output": { "action": "APPROVE", "reason": "…" }   // what the model actually returned
}
```

The verifier's `inference_provenance` check then enforces two things:
1. **The action matches the model's output** — the agent can't claim the model approved when it denied.
2. **The judgment prompt matches the audited one** (pin `EXPECTED_SYSTEM_PROMPT_SHA256`) — a swapped/backdoored prompt is rejected *even from a genuine enclave*.

**Honest boundary:** this proves the model consulted, the criteria used, and faithful reporting are all under the enclave signature. The one thing it does *not* prove is that the remote provider's servers actually ran that model unmodified — that requires the provider to return its *own* attestation (confidential inference, e.g. TEE-hosted models). The `inference` block is designed to carry a `provider_attestation` when available; until then, provenance is anchored at the enclave that made the call.

## Attested consensus (no single model decides)

The deepest unsolved question in the agent space: *why trust a **single** AI's judgment on something that moves money?* If that one model hallucinates, is compromised, or is backdoored, its lone "APPROVE" carries the decision.

Veriform can require a **quorum of independent judges** and bind **every vote** into the receipt. Set `CONSENSUS=1` and the agent runs a panel — a real LLM plus independent rule-based evaluators (and more real models when you add keys) — and only approves if `CONSENSUS_THRESHOLD` of them agree:

```json
"consensus": {
  "threshold": 2, "total": 3, "approvals": 1,
  "votes": [
    {"judge": "llm (gemini-flash-lite-latest)", "action": "DENY",    "reason": "…"},
    {"judge": "scam-heuristic",                  "action": "DENY",    "reason": "…"},
    {"judge": "amount-heuristic",                "action": "APPROVE", "reason": "(rogue judge)"}
  ]
}
```

The verifier's `consensus` check recomputes the tally, confirms the final action genuinely followed from the votes, and — with `EXPECTED_CONSENSUS_THRESHOLD` pinned — rejects any receipt where a compromised agent tried to lower its own bar. **Live result:** with one judge fully compromised to approve everything, a scam request is still **DENIED** (1/3, need 2) — the rogue judge cannot force an approval, and the proof is in the receipt.

**Honest boundary:** this proves a quorum of the judges you *consulted* agreed and the action followed — it doesn't make any individual judge correct, and the judges must be genuinely independent (a shared failure mode defeats a quorum). Remote-model execution still needs a provider attestation (§inference). In the free demo the panel is 1 real LLM + 2 rule-based judges; adding Claude/Ollama keys makes it a true multi-model quorum.

## Full DCAP verification (real Intel silicon, verified offline)

The default `quote_authenticity` check validates the Intel *certificate chain*. Veriform also implements **complete DCAP verification** — every signature in the chain of trust, done offline with no paid service ([`dcap.py`](verifier/app/dcap.py), `POST /verify-dcap`):

```
Intel SGX Root CA
   └─signs→ PCK certificate
              └─signs→ QE report
                         └─binds→ attestation key
                                    └─signs→ TD report  ──contains──► report_data
```

Verified against a **real TDX quote captured from genuine Intel hardware** (`tests/fixtures/real_tdx_quote.hex`), all five links pass:

```
PASS quote_format          TDX v4 quote
PASS att_key_signs_report  attestation key's signature over the TD report is valid
PASS qe_binds_att_key      QE report commits to the attestation key
PASS pck_signs_qe          PCK certificate signed the QE report
PASS chain_to_intel_root   PCK chain validates and roots in the Intel SGX Root CA
```

**This is the guarantee real silicon adds** — the `att_key_signs_report` check verifies the hardware's signature over the *entire* report including `report_data`. It's exactly what the simulator can't fake: the dstack simulator serves a real captured quote but rewrites `report_data` after capture, so full DCAP on a simulator quote **correctly fails** at `att_key_signs_report` (tampering with any byte of the signed report breaks it — proven in the tests). Set `FULL_DCAP=1` on a real-hardware deployment and the same six-check flow runs full DCAP end-to-end. The verifier's real-hardware path is thus built and proven; the only remaining step is producing a quote over *our own* `report_data` on live silicon — a deployment, not a capability.

## Verifiable decision history (attested ledger)

Every attestation elsewhere — including Veriform's own receipts above — is **point-in-time**: one quote proves one decision. But an autonomous agent makes a *sequence* of decisions over its life, and no consumable tool lets an outsider verify that whole history. Veriform's decision ledger does.

Each decision is appended to a hash chain and carries a running policy accumulator, all bound into the signed, quote-anchored payload:

```json
"ledger": {
  "seq": 3, "prev_root": "…", "entry_hash": "…", "root": "…",
  "day": "2026-07-10", "daily_total": 4.0, "daily_limit": 5.0
}
```

`POST /verify-sequence` with a list of receipts then proves three things no single quote can:

- **Completeness** — every decision is present; dropping one breaks the chain (`root_n = sha256(root_{n-1} || entry_hash_n)`).
- **Ordering** — none reordered or inserted (sequence numbers + chained roots).
- **Cross-decision policy** — a cumulative invariant held at *every* step. In the demo, three 2.0-ETH transfers each pass the per-transfer limit, but the third is **denied by the ledger** because it would push the daily total past 5.0 — a policy no per-decision check can enforce and no single attestation can prove.

Tampering is caught every way: drop a decision → broken chain + sequence gap + accumulator mismatch; lie about the running total → the verifier recomputes it independently and rejects.

**Why this is (as far as I can tell) unsolved:** the building blocks exist in isolation — hash-chained logs (blockchains, Certificate Transparency), enclave rollback protection (the ROTE work, monotonic counters). What doesn't exist as a consumable thing is an **enclave-attested, third-party-verifiable agent decision ledger carrying semantic policy invariants**. That's Veriform's "make the proof consumable" thesis extended from one decision to the whole history.

**Honest boundary:** the ledger is tamper-evident *within a presented sequence*. A malicious operator could still roll the enclave back to an earlier state and present a shorter or forked history. Defeating that needs the latest root anchored **outside** the enclave — a hardware monotonic counter, or periodically posting the root on-chain / to a transparency log (which is exactly what the on-chain anchor, Phase 5, is for). The ledger is designed to make that anchoring a one-line addition: you anchor `root`, and the whole history behind it becomes non-forkable.

## Quick start

No TEE hardware needed — dstack ships a local simulator.

```bash
# 0. Tooling
npm install -g phala
phala simulator start            # local TEE simulator

# 1. Run the agent + verifier
docker compose up

# 2. Open the verifier
#    http://localhost:3000 — ask the agent for a decision, watch it verify ✅

# 3. Flip the tamper toggle
#    The "evil" agent forges the same decision without a valid quote → ❌
```

> **Gotcha:** the dstack SDK talks to the enclave over a Unix socket. Every container needs this mount or attestation calls hang:
> ```yaml
> volumes:
>   - /var/run/dstack.sock:/var/run/dstack.sock
> ```

### Windows / no Docker? One command

`phala simulator start` doesn't support Windows yet. [dev-sim/sim.py](dev-sim/sim.py) speaks the same dstack wire protocol (clearly labeled NOT-A-TEE) so the unmodified agent runs anywhere. Launch the whole stack with:

```powershell
pip install fastapi uvicorn httpx eth-account dstack-sdk anthropic
powershell -ExecutionPolicy Bypass -File scripts\run-local.ps1
# open http://localhost:3000
```

It reads `GEMINI_API_KEY` from `.env` (free tier) and falls back to rules-only judging if absent.

### Real Intel TDX silicon

No Phala or Docker needed — on any Intel TDX VM (GCP `c3-standard`, Azure `DCesv6`, kernel ≥ 6.7), one command produces a genuine quote over a real decision and verifies the full chain of trust:

```bash
git clone https://github.com/Sakthi-Sundaram-R/Veriform.git && cd Veriform
bash scripts/tdx-quote.sh    # QUOTE_BACKEND=tsm under the hood
```

This runs $0 on a GCP/Azure free trial. Or deploy the container to Phala Cloud with `bash scripts/deploy-tdx.sh`. Either way the ✅ is now backed by real hardware attestation — see [Phase 3](#phase-3--real-tee-quote-on-live-silicon-ready-one-command).

## Architecture & stack

| Piece | Tech |
|---|---|
| Enclave runtime | Phala dstack (full-VM isolation — deploy unmodified Docker containers) |
| Agent | Python, dstack SDK, LLM API call for decision reasoning |
| Signing | secp256k1 (viem/ethers-compatible, so the on-chain piece is trivial) |
| Verifier | React page; quote verification via Phala's verification endpoint or client-side `dcap-qvl` |
| Tamper demo | Second "evil" container that forges decisions outside the enclave |
| On-chain (stretch) | Minimal Solidity contract on Base Sepolia storing the attested key |

## Roadmap

### ✅ Done
- [x] Problem statement & architecture
- [x] Agent container: decision → hash → quote → signature
- [x] Verifier UI with receipt verification (✅/❌)
- [x] Tamper demo: evil container + toggle
- [x] Live end-to-end run (dev shim on Windows: honest ✅ / evil ❌)
- [x] **Phase 2 — LLM judgment live (free):** pluggable judge (`anthropic | gemini | ollama | none`), all fail closed. Verified with Gemini free tier: legit rent → reasoned APPROVE, giveaway scam → reasoned DENY, both in verified receipts.

### Phase 1 — Official simulator run ✅ DONE
Validated against the **official Phala dstack simulator** (v0.5.3). `phala simulator start` refuses to run on Windows and ships no Windows binary, so the Linux (musl) simulator runs inside a ~3.5 MB Alpine WSL2 distro, reachable from Windows over TCP — see [`scripts/run-official-sim-windows.sh`](scripts/run-official-sim-windows.sh). The honest agent's receipt **VERIFIES** with a real 5006-byte TDX quote ([proof](docs/phase1-official-sim-proof.json)): `quote_present`, `quote_structure`, `enclave_measurement` (real MRTD pinned), `decision_binding`, and `signature` all pass; only `quote_authenticity` is skipped (needs real hardware + Intel PKI, i.e. Phase 3). Evil agents still rejected. This proves the binding scheme, byte offsets, and measurement pinning are correct against the genuine dstack quote format — not just the dev shim.

### Phase 3 — Real TEE quote on live silicon ✅ DONE
**Completed on Phala Cloud Intel TDX** (node prod9, US-WEST-1, `tdx.small`). The agent was deployed to a real TDX CVM, sent a live decision, and returned a genuine **5010-byte TDX v4 quote** signed by the enclave key over *our own* `report_data`. Run through the verifier, **all five DCAP links plus decision binding pass** — including `att_key_signs_report`, the one only real, unpatched silicon can satisfy:

```
[PASS] quote_format          TDX v4 quote
[PASS] att_key_signs_report  hardware signed the TD report over our report_data
[PASS] qe_binds_att_key      QE report commits to the attestation key
[PASS] pck_signs_qe          PCK certificate signed the QE report
[PASS] chain_to_intel_root   roots in the Intel SGX Root CA
[PASS] decision_binding      report_data commits to our decision (APPROVE, rent)
```

The quote is preserved at [`tests/fixtures/live_tdx_quote.hex`](tests/fixtures/live_tdx_quote.hex) with a regression test ([`test_phase3_live.py`](tests/test_phase3_live.py)) and the proof at `docs/phase3-real-quote-proof.json`. Two reproducible paths below.

**Free path — any Intel TDX VM ($0 on a GCP/Azure free trial).**
The agent can generate a quote via the generic Linux TDX interface (`/sys/kernel/config/tsm/report`) with `QUOTE_BACKEND=tsm` — no Phala, no dstack, no Docker. One script does the whole thing:

**Free path — any Intel TDX VM ($0 on a GCP/Azure free trial).**
The agent can generate a quote via the generic Linux TDX interface (`/sys/kernel/config/tsm/report`) with `QUOTE_BACKEND=tsm` — no Phala, no dstack, no Docker. One script does the whole thing:

```bash
# on any Intel TDX guest (GCP c3-standard, Azure DCesv6, kernel >= 6.7):
git clone https://github.com/Sakthi-Sundaram-R/Veriform.git && cd Veriform
bash scripts/tdx-quote.sh
```

It generates a real quote over a live decision, verifies the full Intel chain of trust ([full DCAP](#full-dcap-verification-real-intel-silicon-verified-offline)) plus decision binding, and writes the proof to `docs/phase3-real-quote{.hex,-proof.json}`. A `c3-standard-4` costs ~cents for the ~5 minutes this takes, and GCP's $300 free trial (verifiable with card, **PayPal, or bank account**) covers it — so the cost is $0.

Don't have a TDX VM? You don't need your own — **[`docs/PHASE3-HELPER.md`](docs/PHASE3-HELPER.md)** is a single self-checking block anyone with TDX hardware can paste and send back. The proof is self-standing (a real Intel DCAP chain over our decision), and the doc shows how to independently re-verify the returned quote locally.

**Phala Cloud path.** Agent image is public at `ghcr.io/sakthi-sundaram-r/veriform-agent`; deploy config is [`docker-compose.phala.yaml`](docker-compose.phala.yaml). After `phala login` + a $1 top-up, one script deploys → captures the real TDX quote → tears down:

```bash
bash scripts/deploy-tdx.sh
```

**Done when:** the full chain of trust (`att_key_signs_report` and every DCAP link) passes over our own `report_data` on real Intel TDX silicon, and the evil agent still fails.

### Phase 4 — Demo polish (mostly done)
- [x] Forged-quote toggle in the UI (`decision_binding` failure — quote and signature valid, binding caught)
- [x] 2-minute demo script with judge Q&A: [DEMO.md](DEMO.md)
- [x] Screenshots in the README ([docs/](docs/), all three modes)

### Phase 5 (stretch) — On-chain anchor
Two independent on-chain guarantees: the **signature** path (was the enclave key the signer?) and the **hardware** path (was the quote genuine Intel TDX?).

- [x] [`VeriformRegistry.sol`](contracts/VeriformRegistry.sol) — stores the attested agent key, verifies decision signatures via `ecrecover`
- [x] [`DemoConsumer.sol`](contracts/DemoConsumer.sol) — a contract action gated on "signed by a verified enclave"
- [x] Signature scheme proven ecrecover-compatible with the enclave key (3 tests in [`test_onchain.py`](tests/test_onchain.py))
- [x] **[`AttestedQuoteConsumer.sol`](contracts/AttestedQuoteConsumer.sol) — on-chain DCAP.** Gates an action on **both** (1) [Automata's on-chain DCAP verifier](https://github.com/automata-network/automata-dcap-attestation) accepting the quote (the full Intel chain of trust, enforced in the EVM against on-chain PCCS) and (2) the quote's `report_data` matching `sha256(decisionHash ‖ enclave)`, recomputed on-chain — identical to the enclave's binding. The byte-offset extraction and the on-chain binding recomputation are proven equivalent to the enclave and the off-chain verifier against the real hardware quote (6 tests in [`test_automata.py`](tests/test_automata.py)).
- [x] **Free on-chain verification** — [`scripts/automata_verify.py`](scripts/automata_verify.py) simulates `verifyAndAttestOnChain` with `eth_call` (no wallet, no gas) against the deployed Automata contract (Ethereum Sepolia `0x63eF…5BAf` / Automata `0xd3A3…1483`). Live-tested end to end; a real deployed quote passes once its platform collateral is in the on-chain PCCS.
- [x] **Deploy + gated-action demo** — [`scripts/deploy_onchain.py`](scripts/deploy_onchain.py) compiles all three contracts with `solc 0.8.24` and deploys them (in-memory `eth-tester` by default, or a real chain with `RPC_URL` + `PRIVATE_KEY`), then runs the full gate: a genuine enclave signature **executes** on-chain, the evil agent's is **rejected** (`UnverifiedDecision`).
- [x] **Published live to Ethereum Sepolia** ✅ — deployed and the on-chain gate verified on a public chain (genuine sig executes, impostor reverts):
  | Contract | Address |
  |---|---|
  | VeriformRegistry | [`0x5d0CeA35…3937C`](https://sepolia.etherscan.io/address/0x5d0CeA3564a959959C04B4A9dDc0D6209ED3937C) |
  | DemoConsumer | [`0x03Fb74db…C6B2`](https://sepolia.etherscan.io/address/0x03Fb74db45e3a6282107393be73fC7D12147C6B2) |
  | AttestedQuoteConsumer | [`0x6658DD64…68b8`](https://sepolia.etherscan.io/address/0x6658DD646FaCc994bc358183F2c39FFfd25068b8) |
- [ ] Fully exercise `AttestedQuoteConsumer` on-chain (deployed above) — additionally needs the live quote's platform collateral upserted to Automata's on-chain PCCS.

### Phase 6 (stretch) — Multi-vendor attestation
Require agreement across vendor roots (Intel/AMD/Nvidia) so no single PKI compromise breaks the guarantee.

## Security

Full trust model, per-check defense map, and honest boundaries: **[SECURITY.md](SECURITY.md)**. Short version — the operator (host, root, cloud admin) is untrusted; trust roots only in Intel's pinned PKI and the enclave attestation; the verifier trusts only mathematics. Every rejection is a real cryptographic failure, not a hardcoded check. What's explicitly *out* of scope: liveness/DoS, input confidentiality, remote-model execution, ledger rollback, and replay freshness — each documented with its intended mitigation.

## Why this matters

Agents that handle funds, private data, or autonomous on-chain actions can *technically* be made verifiable today — but in practice no end user or contract can actually verify them without trusting the operator anyway. The trust gap has moved from the hardware up into the application layer. Veriform makes the invisible proof **visible, correct, and hard to fake**.
