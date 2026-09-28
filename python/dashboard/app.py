"""Minimal Flask web dashboard for viewing recent alerts.

Reads the JSON Lines log file written by core/logger.py directly. No database
is required, so the dashboard can be started or restarted without losing or
duplicating state.
"""
from __future__ import annotations

import json
import os
from collections import deque

from flask import Flask, jsonify, render_template


def create_app(log_file: str, max_alerts: int = 200) -> Flask:
    app = Flask(__name__)

    @app.route("/")
    def index():
        return render_template("index.html")

    @app.route("/api/alerts")
    def api_alerts():
        alerts = deque(maxlen=max_alerts)
        if os.path.exists(log_file):
            with open(log_file, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    try:
                        record = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if record.get("type") == "alert":
                        alerts.append(record)
        return jsonify(list(alerts)[::-1])  # newest first

    return app


if __name__ == "__main__":
    import yaml

    with open(os.environ.get("FALCO_CONFIG", "config/config.yaml")) as f:
        cfg = yaml.safe_load(f)

    app = create_app(cfg["logging"]["log_file"])
    app.run(host=cfg["dashboard"]["host"], port=cfg["dashboard"]["port"])
