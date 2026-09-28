"""Detect successful logins considered anomalous because they originate from a
country outside the allowlist or, optionally, occur during nighttime hours.
"""
from __future__ import annotations

import datetime

from core.logger import log_alert
from detectors.base import Detector


class AnomalousLoginDetector(Detector):
    name = "anomalous_login"

    def __init__(self, config: dict, logger, blocker, geoip) -> None:
        super().__init__(config, logger, blocker, geoip)
        self.allowed_countries = set(config.get("allowed_countries", []))
        self.night_hours_alert = config.get("night_hours_alert", True)

    def handle_packet(self, event: dict) -> None:
        return  # Only processes successful login events

    def handle_login(self, event: dict) -> None:
        if not self.enabled or event.get("type") != "login_success":
            return

        ip = event["ip"]
        geo = self.geoip.lookup(ip)
        country = geo.get("country")
        reasons = []

        if self.allowed_countries and country and country not in self.allowed_countries and country != "LAN":
            reasons.append(f"login from an unexpected country ({country})")

        if self.night_hours_alert:
            hour = datetime.datetime.now().hour
            if 0 <= hour < 5:
                reasons.append(f"login during nighttime hours ({hour}:00)")

        if reasons:
            log_alert(self.logger, self.name, "medium", ip, {
                "reason": "; ".join(reasons),
                "user": event.get("user"),
                "geo": geo,
            })
            # No automatic blocking: this could be a legitimate administrator traveling
            # or working outside normal hours. Alert only.
