"""Reputation & abuse limits for Phase 3.

Reputation is a small persistent store keyed by participant identity (a keypair
fingerprint in secure mode, else the node id / requester id). It counts job
outcomes so a node's track record survives reconnects and gateway restarts, and
feeds the matcher (prefer reliable devices, deprioritize flaky ones).

Abuse limits keep a single requester from overwhelming the pool: a sliding-window
rate limit and a concurrency cap. These are in-memory (reset on restart), which
is fine — they bound bursty behavior, not long-term trust.
"""

import json
import os
import tempfile
import time
from collections import defaultdict, deque
from datetime import datetime, timezone

_FIELDS = ("ok", "fail", "evict", "submitted")


def _now_iso():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class ReputationStore:
    def __init__(self, path=None):
        self.path = path
        self.data = {}
        if path and os.path.exists(path):
            try:
                with open(path, encoding="utf-8") as f:
                    self.data = json.load(f)
            except (OSError, ValueError):
                self.data = {}

    def get(self, key: str) -> dict:
        e = self.data.get(key, {})
        return {f: e.get(f, 0) for f in _FIELDS}

    def record(self, key: str, field: str, n: int = 1) -> None:
        e = self.data.setdefault(key, {f: 0 for f in _FIELDS})
        e[field] = e.get(field, 0) + n
        e["last_seen"] = _now_iso()
        self._save()

    def total(self, key: str) -> int:
        """Number of job outcomes recorded (evidence for the score)."""
        e = self.get(key)
        return e["ok"] + e["fail"] + e["evict"]

    def reliability(self, key: str) -> float:
        """Laplace-smoothed success rate: starts at 0.5 for an unknown identity,
        rises toward 1.0 with a good record, falls with failures/evictions."""
        e = self.get(key)
        good = e["ok"]
        bad = e["fail"] + e["evict"]
        return (good + 1) / (good + bad + 2)

    def _save(self) -> None:
        if not self.path:
            return
        d = os.path.dirname(os.path.abspath(self.path))
        os.makedirs(d, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=d, prefix=".rep-")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(self.data, f, indent=2, sort_keys=True)
            os.replace(tmp, self.path)
        finally:
            if os.path.exists(tmp):
                os.remove(tmp)


class RateLimiter:
    """Sliding-window rate limit: at most `max_per_window` events per `window`
    seconds, per key. A max of 0 disables it."""

    def __init__(self, max_per_window: int, window_sec: int = 60):
        self.max = max_per_window
        self.window = window_sec
        self._hits = defaultdict(deque)

    def allow(self, key: str) -> bool:
        if not self.max:
            return True
        now = time.monotonic()
        dq = self._hits[key]
        cutoff = now - self.window
        while dq and dq[0] <= cutoff:
            dq.popleft()
        if len(dq) >= self.max:
            return False
        dq.append(now)
        return True
