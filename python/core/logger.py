"""Central logger for FALCO Guardian.

Writes both to the console (for systemd/journalctl) and to a dedicated file in
JSON Lines format so it can be consumed by operators (`tail -f | jq`) and by
the dashboard.
"""
from __future__ import annotations

import json
import logging
import os
import time
from logging.handlers import RotatingFileHandler


class JsonLineFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(record.created)),
            "level": record.levelname,
            "component": record.name,
            "message": record.getMessage(),
        }
        extra = getattr(record, "extra_fields", None)
        if extra:
            payload.update(extra)
        return json.dumps(payload, ensure_ascii=False)


def setup_logger(log_file: str, level: str = "INFO") -> logging.Logger:
    os.makedirs(os.path.dirname(log_file), exist_ok=True)

    logger = logging.getLogger("falco")
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))
    logger.handlers.clear()

    file_handler = RotatingFileHandler(log_file, maxBytes=10 * 1024 * 1024, backupCount=5)
    file_handler.setFormatter(JsonLineFormatter())
    logger.addHandler(file_handler)

    console_handler = logging.StreamHandler()
    console_handler.setFormatter(logging.Formatter("[%(asctime)s] %(name)s %(levelname)s: %(message)s"))
    logger.addHandler(console_handler)

    return logger


def log_alert(logger: logging.Logger, detector: str, severity: str, ip: str, details: dict) -> None:
    """Write a structured alert used by all detectors."""
    logger.warning(
        f"[{detector}] alert for {ip}: {details.get('reason', '')}",
        extra={"extra_fields": {
            "type": "alert",
            "detector": detector,
            "severity": severity,
            "ip": ip,
            **details,
        }},
    )
