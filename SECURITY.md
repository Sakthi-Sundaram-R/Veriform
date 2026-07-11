# Veriform — Threat Model & Security Rationale

This document states precisely what Veriform protects, against whom, how each
check contributes, and — just as importantly — what it does **not** protect.
Honesty about the boundaries is deliberate: a verification system that
overstates its guarantees is worse than one that states them exactly.

---

## 1. What Veriform protects

**Goal:** let any third party — a user, an auditor, or a smart contract —
confirm, without trusting the operator, that a decision (and a whole history of
decisions) came from a genuine, unaltered agent running in a hardware enclave,
under audited judgment criteria.

The protected asset is **the integrity and provenance of an agent's decisions**,
not the confidentiality of its inputs (see §5).

---

## 2. Trust model

| Party / component | Trusted? | Notes |
|---|---|---|
| **Intel** (SGX/TDX hardware + PKI root) | **Yes** (root of trust) | The Intel SGX Root CA public key is pinned; all attestation trust chains to it. |
| **The TEE / enclave** | Yes, *if attested* | Trusted only insofar as a valid quote proves unaltered code + sealed keys. |
| **The enclave-derived signing key** | Yes | Derived inside the TEE, never leaves it. |
| **The operator / host** (server, root user, cloud admin) | **No** | Can read/alter anything outside the enclave, control the network, restart or roll back the process. |
| **The agent's own code** | Trusted *only* via measurement | Pin `EXPECTED_MRTD`; a different build is rejected. |
| **The LLM judgment prompt** | Trusted *only* via hash | Pin `EXPECTED_SYSTEM_PROMPT_SHA256`; a swapped prompt is rejected. |
| **The remote LLM provider's servers** | **No** (see §5) | Their execution is attested only if they return their own attestation. |
| **The verifier** | Trusts only mathematics | Shares no secret with the agent; everything it checks is recomputable from the receipt + public knowledge. |

**Adversary:** a malicious or compromised operator with full control of the host
and network, who wants a forged, altered, or policy-violating decision to be
accepted as genuine.

---

## 3. Per-check defense map

Each receipt carries checks; a full history adds sequence-level checks. Every
rejection is for a real cryptographic reason — there is no hardcoded "if evil".

| Check | Defends against | Mechanism |
|---|---|---|
| `quote_present` | An impostor running **outside any enclave** | No attestation quote → reject. |
| `quote_structure` | Malformed / truncated quotes | Must parse as a TDX-quote-sized structure. |
| `enclave_measurement` | **Different (backdoored) code** in a genuine enclave | Quote's `MRTD` must equal the pinned known-good build. |
| `decision_binding` | **Altering the decision**, or **replaying** a quote for a different decision | `report_data` must equal `sha256(decision_hash ‖ address)`. |
| `signature` | **Tampered payload**, wrong signer | Signature over the canonical payload must recover to the attested key. |
| `inference_provenance` | **Backdoored judgment prompt** in a genuine enclave; agent **lying about the model's output** | Judgment prompt hash must match the pinned audited one; action must match the model's actual output. |
| `ledger_link` | A malformed history link; an over-limit accumulator on a single receipt | `root = sha256(prev_root ‖ entry_hash)`; `daily_total ≤ daily_limit`. |
| `quote_authenticity` (chain) | Forged quotes with **no genuine Intel collateral** | PCK chain must root in the pinned Intel SGX Root CA. |
| `quote_authenticity` (full DCAP, `FULL_DCAP=1`) | A quote whose **report was altered after the hardware signed it** | Full chain: Intel root → PCK → QE report → attestation key → TD report. Catches any post-signing modification. |

### History-level (`verify_sequence`)

| Property | Defends against | Mechanism |
|---|---|---|
| **Completeness** | Silently **dropping** a decision | Missing link breaks the hash chain + sequence gap. |
| **Ordering** | **Reordering / inserting** decisions | Chained roots + monotonic sequence numbers. |
| **Policy invariant** | Approving beyond a **cross-decision limit**; **lying** about the running total | Verifier recomputes the accumulator independently and rejects a breach or mismatch. |

---

## 4. Demonstrated attacks (all rejected)

| Attack | Caught by |
|---|---|
| Agent runs outside the enclave, no quote | `quote_present` |
| Agent forges a structurally valid but fake quote | `decision_binding` (+ `enclave_measurement`) |
| Genuine enclave, valid quote & signature, but **backdoored judgment prompt** | `inference_provenance` |
| Decision payload altered after signing | `decision_binding` + `signature` |
| Signature from a non-enclave key | `signature` |
| A decision **dropped** from the history | ledger completeness |
| Agent **lies** about its cumulative total | ledger policy invariant |
| **Any byte of a signed hardware report altered** (incl. a simulator patching `report_data`) | full DCAP `att_key_signs_report` |

---

## 5. What Veriform does **not** protect (honest boundaries)

These are out of scope by design, or require a step not yet taken. Stating them
is part of the guarantee.

1. **Liveness / denial of service.** A malicious operator can always *refuse to
   run* the agent or drop its messages. Veriform proves nothing was **forged or
   altered**; it cannot force the operator to act. Availability is out of scope.

2. **Confidentiality of inputs.** In this version the operator can still see the
   transaction request going *into* the enclave. Veriform protects the
   integrity of the decision, not the privacy of the input. (Encrypting inputs
   *to* the enclave — confidential inputs — is a natural extension.)

3. **Remote LLM execution.** `inference_provenance` proves *which* model was
   consulted, under *which* audited prompt, and that the agent reported the
   model's output faithfully. It does **not** prove the provider's servers ran
   that model unmodified — that requires the provider to return its own
   attestation (confidential inference). The `inference` block is designed to
   carry a `provider_attestation` when one is available.

4. **Ledger rollback / forking.** The decision ledger is tamper-evident *within
   a presented sequence*. A malicious operator could still roll the enclave back
   to an earlier state and present a shorter or forked history. Non-forkability
   requires the latest root to be anchored **outside** the enclave — a hardware
   monotonic counter, or periodically posting the root on-chain / to a
   transparency log. The ledger is built so this anchoring is a one-line
   addition.

5. **Replay / freshness.** A receipt is currently valid indefinitely — an old
   valid "APPROVE" could be replayed. Mitigation (a per-decision nonce +
   expiry, or the ledger sequence as a monotonic guard) is a known, not-yet-
   implemented gap.

6. **Binding our own decision on live silicon.** The verifier's full-DCAP path
   is **built and proven** against a real hardware quote. Producing a quote over
   *our own* `report_data` on live Intel silicon is a **deployment step**, not a
   missing capability — it needs a confidential VM, which was blocked only on
   account/billing access, never on engineering.

7. **Key compromise.** If the enclave signing key were extracted (which the TEE
   is designed to prevent), forged receipts would pass. Key rotation under fresh
   attestation is supported in principle; automated rotation is not implemented.

8. **Side channels / TEE breaks.** Veriform inherits the security of the
   underlying TEE. A hardware vulnerability (speculative-execution side channel,
   etc.) is out of scope and is the vendor's domain; multi-vendor attestation
   (requiring agreement across Intel/AMD/Nvidia roots) is the intended
   mitigation against a single-vendor compromise.

---

## 6. Assumptions

- The Intel SGX Root CA pinned key (`a0af0312…`) is authentic. (It is the
  widely published Intel root; in production, verify out-of-band.)
- The known-good `MRTD` and audited system-prompt hash are pinned from a build
  the verifier's operator actually audited — the checks are only as strong as
  what is pinned.
- Standard cryptographic assumptions: SHA-256 collision resistance, ECDSA-P256
  and secp256k1 unforgeability, X.509 chain validity.

---

*Veriform is a research/portfolio project. It composes standard primitives into
a consumable verification layer; it does not introduce new cryptography, and it
has not undergone formal security review. Treat the guarantees above as design
intent supported by tests, not as a certified security product.*
