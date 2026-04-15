from __future__ import annotations

import hashlib
import ipaddress
import json
import time
from dataclasses import dataclass
from urllib.error import URLError
from urllib.request import urlopen


@dataclass(slots=True)
class GeoResult:
    ip: str
    latitude: float
    longitude: float
    country: str | None
    city: str | None
    source: str


class GeoService:
    def __init__(self) -> None:
        self._cache: dict[str, tuple[float, GeoResult]] = {}
        self._ttl_seconds = 60 * 60 * 24

    def locate_ip(self, ip: str | None) -> GeoResult | None:
        if not ip:
            return None

        now = time.time()
        cached = self._cache.get(ip)
        if cached and cached[0] > now:
            return cached[1]

        try:
            result = self._locate_via_public_api(ip)
        except Exception:  # noqa: BLE001
            result = self._locate_fallback(ip)

        self._cache[ip] = (now + self._ttl_seconds, result)
        return result

    def _locate_via_public_api(self, ip: str) -> GeoResult:
        with urlopen(f"http://ip-api.com/json/{ip}?fields=status,country,city,lat,lon", timeout=1.8) as resp:
            payload = json.loads(resp.read().decode("utf-8"))

        if payload.get("status") != "success":
            return self._locate_fallback(ip)

        return GeoResult(
            ip=ip,
            latitude=float(payload.get("lat") or 0.0),
            longitude=float(payload.get("lon") or 0.0),
            country=payload.get("country"),
            city=payload.get("city"),
            source="ip-api",
        )

    def _locate_fallback(self, ip: str) -> GeoResult:
        # Private ranges are mapped to a fixed local coordinate for stable rendering.
        try:
            addr = ipaddress.ip_address(ip)
            if addr.is_private:
                return GeoResult(
                    ip=ip,
                    latitude=31.2304,
                    longitude=121.4737,
                    country="Private Network",
                    city="Local",
                    source="fallback-private",
                )
        except ValueError:
            pass

        digest = hashlib.md5(ip.encode("utf-8")).hexdigest()
        lat_seed = int(digest[:8], 16)
        lon_seed = int(digest[8:16], 16)
        lat = (lat_seed % 14000) / 100 - 70
        lon = (lon_seed % 36000) / 100 - 180

        return GeoResult(
            ip=ip,
            latitude=round(lat, 4),
            longitude=round(lon, 4),
            country="Unknown",
            city="Unknown",
            source="fallback-hash",
        )


geo_service = GeoService()
