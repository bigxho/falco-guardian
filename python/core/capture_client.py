"""Client for the eBPF/C component (ebpf/src/loader.c).

Connects to the Unix socket where the loader sends one JSON event per line
(one for each packet captured at kernel level) and forwards deserialized
events to a callback. It reconnects automatically if the C loader has not
started yet or is restarted.
"""
from __future__ import annotations

import json
import logging
import socket
import threading
import time
from typing import Callable

log = logging.getLogger("falco.capture_client")

PacketHandler = Callable[[dict], None]


class CaptureClient:
    def __init__(self, socket_path: str, on_packet: PacketHandler) -> None:
        self.socket_path = socket_path
        self.on_packet = on_packet
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        self._thread = threading.Thread(target=self._run, name="capture-client", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                self._connect_and_read()
            except (FileNotFoundError, ConnectionRefusedError):
                log.debug("eBPF loader is not available yet at %s; retrying in 3s", self.socket_path)
            except Exception as exc:
                log.warning("Connection to the eBPF loader interrupted: %s", exc)
            time.sleep(3)

    def _connect_and_read(self) -> None:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.connect(self.socket_path)
            log.info("Connected to the eBPF loader at %s", self.socket_path)
            buf = b""
            while not self._stop.is_set():
                chunk = sock.recv(4096)
                if not chunk:
                    break
                buf += chunk
                while b"\n" in buf:
                    line, buf = buf.split(b"\n", 1)
                    if not line:
                        continue
                    try:
                        event = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    try:
                        self.on_packet(event)
                    except Exception:
                        log.exception("Error while processing a packet event")
