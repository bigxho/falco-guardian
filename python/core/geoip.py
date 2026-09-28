"""IP geolocation based on a local MaxMind GeoLite2 database.

No external network lookup is performed. Download the database separately and
reference it in config.yaml.
"""
from __future__ import annotations

import ipaddress
import logging

log = logging.getLogger("falco.geoip")

try:
    import geoip2.database
except ImportError:  # pragma: no cover - optional dependency
    geoip2 = None  # type: ignore


class GeoIP:
    def __init__(self, database_path: str, enabled: bool = True) -> None:
        self.enabled = enabled and geoip2 is not None
        self._reader = None
        if self.enabled:
            try:
                self._reader = geoip2.database.Reader(database_path)
            except Exception as exc:  # missing or corrupted file, etc.
                log.warning("Unable to load the GeoIP database (%s): %s", database_path, exc)
                self.enabled = False

    def lookup(self, ip: str) -> dict:
        """Return geolocation fields or an empty dictionary when unavailable."""
        if not self.enabled:
            return {}
        try:
            addr = ipaddress.ip_address(ip)
            if addr.is_private or addr.is_loopback:
                return {"country": "LAN", "city": "-", "lat": None, "lon": None}
        except ValueError:
            return {}

        try:
            resp = self._reader.city(ip)
            return {
                "country": resp.country.iso_code,
                "city": resp.city.name,
                "lat": resp.location.latitude,
                "lon": resp.location.longitude,
            }
        except Exception:
            return {}
