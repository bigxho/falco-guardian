"""Shared in-memory state: per-IP counters with sliding time windows.

Used by all detectors to track how often an event occurred for an IP during
the last N seconds without duplicating state logic. Thread-safe because the
capture client and authentication-log watcher run on separate threads.
"""
from __future__ import annotations

import threading
import time
from collections import defaultdict, deque
from typing import Deque, Dict


class SlidingWindowCounter:
    """Count events for a key, typically an IP address, within a time window."""

    def __init__(self) -> None:
        self._events: Dict[str, Deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def add(self, key: str, window_seconds: float, now: float | None = None) -> int:
        """Record an event for `key` and return the count within the window."""
        now = now if now is not None else time.time()
        with self._lock:
            dq = self._events[key]
            dq.append(now)
            cutoff = now - window_seconds
            while dq and dq[0] < cutoff:
                dq.popleft()
            return len(dq)

    def count(self, key: str, window_seconds: float, now: float | None = None) -> int:
        now = now if now is not None else time.time()
        with self._lock:
            dq = self._events.get(key)
            if not dq:
                return 0
            cutoff = now - window_seconds
            while dq and dq[0] < cutoff:
                dq.popleft()
            return len(dq)


class DistinctSetWindow:
    """Like SlidingWindowCounter, but counts distinct values such as ports per IP."""

    def __init__(self) -> None:
        self._events: Dict[str, Deque[tuple[float, object]]] = defaultdict(deque)
        self._lock = threading.Lock()

    def add(self, key: str, value: object, window_seconds: float, now: float | None = None) -> int:
        now = now if now is not None else time.time()
        with self._lock:
            dq = self._events[key]
            dq.append((now, value))
            cutoff = now - window_seconds
            while dq and dq[0][0] < cutoff:
                dq.popleft()
            return len({v for _, v in dq})


class ByteCounterWindow:
    """Sum bytes per key within a time window for the exfiltration detector."""

    def __init__(self) -> None:
        self._events: Dict[str, Deque[tuple[float, int]]] = defaultdict(deque)
        self._lock = threading.Lock()

    def add(self, key: str, num_bytes: int, window_seconds: float, now: float | None = None) -> int:
        now = now if now is not None else time.time()
        with self._lock:
            dq = self._events[key]
            dq.append((now, num_bytes))
            cutoff = now - window_seconds
            while dq and dq[0][0] < cutoff:
                dq.popleft()
            return sum(b for _, b in dq)
