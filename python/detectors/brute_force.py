"""Detect SSH brute-force activity: too many failed login attempts from the
same IP address within a time window, based on core/authlog_watcher.py events.
"""
from __future__ import annotations

from core.logger import log_alert
from core.state import SlidingWindowCounter
from detectors.base import Detector


class BruteForceDetector(Detector):
    name = "brute_force"

    def __init__(self, config: dict, logger, blocker, geoip) -> None:
        super().__init__(config, logger, blocker, geoip)
        self.max_attempts = config.get("max_failed_attempts", 5)
        self.window = config.get("window_seconds", 120)
        self._failures = SlidingWindowCounter()
        self._alerted_recently: set[str] = set()

    def handle_packet(self, event: dict) -> None:
        return  # This detector only processes login events

    def handle_login(self, event: dict) -> None:
        if not self.enabled or event.get("type") != "login_failed":
            return

        ip = event["ip"]
        count = self._failures.add(ip, self.window)

        if count >= self.max_attempts and ip not in self._alerted_recently:
            self._alerted_recently.add(ip)
            geo = self.geoip.lookup(ip)
            log_alert(self.logger, self.name, "high", ip, {
                "reason": f"{count} failed login attempts in {self.window}s (user: {event.get('user')})",
                "failed_attempts": count,
                "geo": geo,
            })
            self.blocker.block(ip, reason="brute force SSH")
