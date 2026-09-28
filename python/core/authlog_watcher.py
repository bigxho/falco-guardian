"""Tail the authentication log (/var/log/auth.log on Debian) to extract
failed and successful SSH login attempts.

Network events captured through eBPF show who communicates with whom, but not
who authenticated. Brute-force and anomalous-login detection requires this log.
"""
from __future__ import annotations

import logging
import re
import threading
import time
from typing import Callable

log = logging.getLogger("falco.authlog")

LoginHandler = Callable[[dict], None]

FAILED_RE = re.compile(r"Failed password for (invalid user )?(?P<user>\S+) from (?P<ip>[\d.]+)")
ACCEPTED_RE = re.compile(r"Accepted \S+ for (?P<user>\S+) from (?P<ip>[\d.]+)")


class AuthLogWatcher:
    def __init__(self, log_path: str, on_event: LoginHandler) -> None:
        self.log_path = log_path
        self.on_event = on_event
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        self._thread = threading.Thread(target=self._run, name="authlog-watcher", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                self._tail()
            except FileNotFoundError:
                log.warning("%s not found; retrying in 5s (is this the correct path for the distribution?)", self.log_path)
                time.sleep(5)
            except Exception:
                log.exception("Error while reading %s", self.log_path)
                time.sleep(5)

    def _tail(self) -> None:
        with open(self.log_path, "r", encoding="utf-8", errors="ignore") as f:
            f.seek(0, 2)  # Start at the end; only new events are relevant
            while not self._stop.is_set():
                line = f.readline()
                if not line:
                    time.sleep(0.5)
                    continue
                self._parse_line(line)

    def _parse_line(self, line: str) -> None:
        m = FAILED_RE.search(line)
        if m:
            self.on_event({"type": "login_failed", "ip": m.group("ip"), "user": m.group("user")})
            return
        m = ACCEPTED_RE.search(line)
        if m:
            self.on_event({"type": "login_success", "ip": m.group("ip"), "user": m.group("user")})
