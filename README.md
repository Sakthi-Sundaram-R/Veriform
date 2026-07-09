# Veriform

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

### Windows / no Docker? Use the dev shim

`phala simulator start` doesn't support Windows yet. [dev-sim/sim.py](dev-sim/sim.py) speaks the same dstack wire protocol (clearly labeled NOT-A-TEE) so the unmodified agent runs anywhere:

```bash
pip install fastapi uvicorn httpx eth-account dstack-sdk anthropic

# four terminals (or background jobs):
uvicorn sim:app --port 8090 --app-dir dev-sim
DSTACK_SIMULATOR_ENDPOINT=http://localhost:8090 uvicorn app.main:app --port 8001 --app-dir agent
uvicorn app.main:app --port 8002 --app-dir evil-agent
uvicorn app.main:app --port 3000 --app-dir verifier
```

### Deploy to a real TEE

Same container, real Intel TDX silicon:

```bash
phala auth login
phala deploy -c docker-compose.yaml -n veriform-agent
phala cvms attestation <cvm-id>    # genuine hardware quote
```

Point the verifier at the deployed URL — the ✅ is now backed by real hardware attestation.

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

- [x] Problem statement & architecture
- [x] Agent container: decision → hash → quote → signature
- [x] Verifier UI with receipt verification (✅/❌)
- [x] Tamper demo: evil container + toggle
- [ ] Deploy to real TDX on Phala Cloud
- [ ] Stretch: on-chain attested-key registry
- [ ] Stretch: multi-vendor attestation (require agreement across Intel/AMD/Nvidia roots)

## Why this matters

Agents that handle funds, private data, or autonomous on-chain actions can *technically* be made verifiable today — but in practice no end user or contract can actually verify them without trusting the operator anyway. The trust gap has moved from the hardware up into the application layer. Veriform makes the invisible proof **visible, correct, and hard to fake**.
