"""Attested decision ledger — extends single-decision receipts to a verifiable
DECISION HISTORY.

Each decision is appended to a hash chain and carries a running policy
accumulator. Because the whole `ledger` block is part of the signed, quote-
bound payload, an outsider can later verify — without trusting the operator —
that a *sequence* of receipts is:

  * complete   — every decision is present (none silently dropped),
  * ordered    — none reordered or inserted,
  * compliant  — a cross-decision invariant (cumulative approved amount within
                 a daily limit) held at every step.

Chain:  root_0 = 32 zero bytes
        entry_hash_n = sha256(canonical(decision_core_n))
        root_n       = sha256(root_{n-1} || entry_hash_n)

`decision_core` is the decision minus the ledger block itself (so the root
never has to commit to its own value).

HONEST BOUNDARY: this is tamper-evident *within a presented sequence*. A
malicious operator could still roll the enclave back to an earlier state and
present a shorter/forked history. Defeating that needs the latest root
anchored outside the enclave — a hardware monotonic counter, or periodically
posting the root on-chain / to a transparency log (ties into the on-chain
anchor). See docs.
"""

import hashlib
import json
import threading
from datetime import datetime, timezone

ZERO_ROOT = "00" * 32


def entry_hash(decision_core: dict) -> str:
    canon = json.dumps(decision_core, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(canon).hexdigest()


def next_root(prev_root: str, e_hash: str) -> str:
    return hashlib.sha256(bytes.fromhex(prev_root) + bytes.fromhex(e_hash)).hexdigest()


class DecisionLedger:
    """In-process append-only ledger with a cumulative daily-approval invariant.

    In-memory for the demo; a production enclave would persist this in sealed
    storage and anchor the root externally for rollback protection.
    """

    def __init__(self, daily_limit: float):
        self.daily_limit = daily_limit
        self._lock = threading.Lock()
        self._seq = 0
        self._root = ZERO_ROOT
        self._day = None
        self._daily_total = 0.0

    def _roll_day(self, now: datetime) -> None:
        today = now.date().isoformat()
        if today != self._day:
            self._day = today
            self._daily_total = 0.0

    def would_breach(self, amount: float, action: str, now: datetime | None = None) -> bool:
        """True if approving `amount` now would exceed the daily limit."""
        now = now or datetime.now(timezone.utc)
        with self._lock:
            self._roll_day(now)
            return action == "APPROVE" and (self._daily_total + amount) > self.daily_limit

    def append(self, decision_core: dict, amount: float, action: str,
               now: datetime | None = None) -> dict:
        """Append a decision and return its ledger block."""
        now = now or datetime.now(timezone.utc)
        with self._lock:
            self._roll_day(now)
            e_hash = entry_hash(decision_core)
            prev_root = self._root
            root = next_root(prev_root, e_hash)
            self._seq += 1
            self._root = root
            if action == "APPROVE":
                self._daily_total += amount
            return {
                "seq": self._seq,
                "prev_root": prev_root,
                "entry_hash": e_hash,
                "root": root,
                "day": self._day,
                "daily_total": round(self._daily_total, 8),
                "daily_limit": self.daily_limit,
            }
