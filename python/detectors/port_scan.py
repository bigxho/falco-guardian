"""Detect port scanning: a source IP contacting an unusual number of distinct
destination ports within a short time window.
"""
from __future__ import annotations

from core.logger import log_alert
from core.state import DistinctSetWindow
from detectors.base import Detector

SYN_FLAG = 0b10  # bit 1 of the tcp_flags field in common.h


class PortScanDetector(Detector):
    name = "port_scan"

    def __init__(self, config: dict, logger, blocker, geoip) -> None:
        super().__init__(config, logger, blocker, geoip)
        self.threshold = config.get("distinct_ports_threshold", 15)
        self.window = config.get("window_seconds", 30)
        self._ports_seen = DistinctSetWindow()
        self._alerted_recently: set[str] = set()

    def handle_packet(self, event: dict) -> None:
        if not self.enabled:
            return
        # Only consider TCP packets with SYN set (connection attempts). This is a
        # cleaner scanning signal and avoids false positives from response traffic.
        if event.get("protocol") != 6:  # IPPROTO_TCP
            return
        if not (event.get("tcp_flags", 0) & SYN_FLAG):
            return

        src_ip = event["src_ip"]
        dst_port = event["dst_port"]
        count = self._ports_seen.add(src_ip, dst_port, self.window)

        if count >= self.threshold and src_ip not in self._alerted_recently:
            self._alerted_recently.add(src_ip)
            geo = self.geoip.lookup(src_ip)
            log_alert(self.logger, self.name, "high", src_ip, {
                "reason": f"{count} distinct ports contacted in {self.window}s",
                "distinct_ports": count,
                "geo": geo,
            })
            self.blocker.block(src_ip, reason="port scan")
