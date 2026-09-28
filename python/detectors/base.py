"""Common interface implemented by all detectors."""
from __future__ import annotations

from abc import ABC, abstractmethod


class Detector(ABC):
    name: str = "base"

    def __init__(self, config: dict, logger, blocker, geoip) -> None:
        self.config = config
        self.logger = logger
        self.blocker = blocker
        self.geoip = geoip
        self.enabled = config.get("enabled", True)

    @abstractmethod
    def handle_packet(self, event: dict) -> None:
        """Called for each packet captured through eBPF when required by the detector."""

    def handle_login(self, event: dict) -> None:
        """Called for each SSH login event when required. Default: ignore."""
        return
