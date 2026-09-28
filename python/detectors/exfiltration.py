"""Detect possible data exfiltration when outbound traffic volume to a single
external IP exceeds a threshold within a time window.

Note: outbound direction is approximated here. On a real interface this
heuristic should be refined for the deployment scenario, for example by using
the `direction` field already reserved in common.h if a TC egress program is
added in the future.
"""
from __future__ import annotations

import ipaddress

from core.logger import log_alert
from core.state import ByteCounterWindow
from detectors.base import Detector


class ExfiltrationDetector(Detector):
    name = "exfiltration"

    def __init__(self, config: dict, logger, blocker, geoip) -> None:
        super().__init__(config, logger, blocker, geoip)
        self.threshold_bytes = config.get("bytes_threshold_mb", 200) * 1024 * 1024
        self.window = config.get("window_seconds", 60)
        self._bytes_out = ByteCounterWindow()
        self._alerted_recently: set[str] = set()

    @staticmethod
    def _is_external(ip: str) -> bool:
        try:
            return not ipaddress.ip_address(ip).is_private
        except ValueError:
            return False

    def handle_packet(self, event: dict) -> None:
        if not self.enabled:
            return
        dst_ip = event.get("dst_ip")
        if not dst_ip or not self._is_external(dst_ip):
            return

        total = self._bytes_out.add(dst_ip, event.get("len", 0), self.window)

        if total >= self.threshold_bytes and dst_ip not in self._alerted_recently:
            self._alerted_recently.add(dst_ip)
            geo = self.geoip.lookup(dst_ip)
            mb = total / (1024 * 1024)
            log_alert(self.logger, self.name, "medium", dst_ip, {
                "reason": f"{mb:.1f} MB sent in {self.window}s to a single external host",
                "bytes_sent": total,
                "geo": geo,
            })
            # Do not block automatically by default: a false positive (backup, sync)
            # could interrupt legitimate outbound traffic.
