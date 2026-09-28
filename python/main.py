"""FALCO Guardian entry point.

Starts:
  - the client receiving packet events from the eBPF/C loader
  - the SSH authentication-log watcher
  - all detectors enabled in config.yaml
  - the Flask dashboard in a separate thread

The eBPF component (ebpf/build/loader) must be started separately as a
privileged process (see systemd/falco-ebpf.service). main.py only connects to
its Unix socket as a client.
"""
from __future__ import annotations

import logging
import os
import sys
import threading
import time

import yaml

sys.path.insert(0, os.path.dirname(__file__))  # allow imports such as "from core..." and "from detectors..."

from core.authlog_watcher import AuthLogWatcher
from core.blocker import Blocker
from core.capture_client import CaptureClient
from core.geoip import GeoIP
from core.logger import setup_logger
from detectors.anomalous_login import AnomalousLoginDetector
from detectors.brute_force import BruteForceDetector
from detectors.exfiltration import ExfiltrationDetector
from detectors.port_scan import PortScanDetector

DETECTOR_CLASSES = {
    "port_scan": PortScanDetector,
    "brute_force": BruteForceDetector,
    "exfiltration": ExfiltrationDetector,
    "anomalous_login": AnomalousLoginDetector,
}


def load_config(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def main() -> None:
    config_path = os.environ.get("FALCO_CONFIG", os.path.join(os.path.dirname(__file__), "..", "config", "config.yaml"))
    cfg = load_config(config_path)

    logger = setup_logger(cfg["logging"]["log_file"], cfg["logging"].get("level", "INFO"))
    logger.info("FALCO Guardian is starting...")

    geoip = GeoIP(cfg["geoip"]["database_path"], enabled=cfg["geoip"].get("enabled", True))
    blocker = Blocker(
        enabled=cfg["blocker"].get("enabled", False),
        block_duration_minutes=cfg["blocker"].get("block_duration_minutes", 60),
        whitelist=cfg["blocker"].get("whitelist", []),
    )

    detectors = []
    for key, cls in DETECTOR_CLASSES.items():
        det_cfg = cfg["detectors"].get(key, {})
        detectors.append(cls(det_cfg, logger, blocker, geoip))

    def on_packet(event: dict) -> None:
        for det in detectors:
            det.handle_packet(event)

    def on_login(event: dict) -> None:
        for det in detectors:
            det.handle_login(event)

    capture_client = CaptureClient(cfg["network"]["capture_socket"], on_packet)
    capture_client.start()

    authlog_cfg = cfg["detectors"].get("brute_force", {})
    authlog_watcher = AuthLogWatcher(authlog_cfg.get("auth_log_path", "/var/log/auth.log"), on_login)
    authlog_watcher.start()

    dashboard_thread = threading.Thread(
        target=_run_dashboard, args=(cfg,), daemon=True, name="dashboard"
    )
    dashboard_thread.start()

    logger.info("FALCO Guardian started. Listening on %s", cfg["network"]["capture_socket"])

    try:
        while True:
            time.sleep(60)
            blocker.unblock_expired()
    except KeyboardInterrupt:
        logger.info("Shutdown requested; stopping...")
        capture_client.stop()
        authlog_watcher.stop()


def _run_dashboard(cfg: dict) -> None:
    # Import here so an environment without Flask can still start the detection layer.
    from dashboard.app import create_app

    app = create_app(cfg["logging"]["log_file"])
    app.run(host=cfg["dashboard"]["host"], port=cfg["dashboard"]["port"], use_reloader=False)


if __name__ == "__main__":
    main()
