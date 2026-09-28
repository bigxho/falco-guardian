"""Automatic blocking of suspicious IP addresses through iptables.

With `enabled: false` in config.yaml, the component only logs what it would do
and does not modify iptables. This is useful for testing on a VM before
enabling blocking on a production server.
"""
from __future__ import annotations

import logging
import subprocess
import threading
import time
from typing import Dict, Iterable

log = logging.getLogger("falco.blocker")


class Blocker:
    def __init__(self, enabled: bool, block_duration_minutes: int, whitelist: Iterable[str]) -> None:
        self.enabled = enabled
        self.block_duration = block_duration_minutes * 60
        self.whitelist = set(whitelist)
        self._blocked_until: Dict[str, float] = {}
        self._lock = threading.Lock()

    def block(self, ip: str, reason: str) -> None:
        if ip in self.whitelist:
            log.info("IP %s is whitelisted; block ignored (%s)", ip, reason)
            return

        with self._lock:
            already_blocked = ip in self._blocked_until and self._blocked_until[ip] > time.time()
            self._blocked_until[ip] = time.time() + self.block_duration

        if already_blocked:
            return  # Already blocked; avoid inserting the same iptables rule again

        if not self.enabled:
            log.warning("[DRY-RUN] would block %s for %ds (reason: %s)", ip, self.block_duration, reason)
            return

        try:
            subprocess.run(
                ["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"],
                check=True, capture_output=True, text=True,
            )
            log.warning("IP %s blocked for %ds (reason: %s)", ip, self.block_duration, reason)
        except subprocess.CalledProcessError as exc:
            log.error("Error blocking %s through iptables: %s", ip, exc.stderr)

    def unblock_expired(self) -> None:
        """Call periodically (for example, once per minute) to remove expired blocks."""
        now = time.time()
        with self._lock:
            expired = [ip for ip, until in self._blocked_until.items() if until <= now]
            for ip in expired:
                del self._blocked_until[ip]

        for ip in expired:
            if self.enabled:
                subprocess.run(
                    ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
                    capture_output=True, text=True,
                )
            log.info("Expired block removed for %s", ip)
