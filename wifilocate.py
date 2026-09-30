#!/usr/bin/env python3
"""wifilocate.py — Apple WLOC geolocation library: BSSID -> coordinates. No API key.

Usage:
    from wifilocate import HuyLocationAlgorithm

    geo = HuyLocationAlgorithm()
    loc = geo.geolocate()                                   # full auto (netsh scan)
    loc = geo.geolocate(wifi_access_points="24:0b:2b:11:5d:d9")
    loc = geo.geolocate(wifi_access_points=["aa:bb:cc:dd:ee:ff", ...])
    loc = geo.geolocate(wifi_access_points=aps)             # list[AccessPoint]

    loc.latitude, loc.longitude, loc.accuracy, loc.confidence

One-shot: from wifilocate import geolocate; loc = geolocate()

Pure layers (codec/algo) have no IO — 1:1 portable to C++/ESP32.
Exit usage: run `python wifilocate.py` for smoke test.
"""

from __future__ import annotations

import gzip
import http.client
import json
import logging
import math
import re
import ssl
import subprocess
import sys
import time
import traceback
import urllib.parse
from dataclasses import dataclass
from typing import Any, Sequence

VERSION = "3.0.0"

ENDPOINTS = {
    "apple": "https://gs-loc.apple.com/clls/wloc",
    "grapheneos": "https://gs-loc.apple.grapheneos.org/clls/wloc",
}
DEFAULT_ENDPOINT = "apple"
APPLE_UA = "locationd/1753.17 CFNetwork/711.1.12 Darwin/14.0.0"
HEADERS = {
    "Content-Type": "application/x-www-form-urlencoded",
    "Accept": "*/*",
    "Accept-Charset": "utf-8",
    "Accept-Encoding": "gzip, deflate",
    "Accept-Language": "en-us",
    "User-Agent": APPLE_UA,
}

ENVELOPE_LEN, MAX_PAYLOAD, RES_HDR = 50, 255, 10
SCALE, SENTINEL = 1e8, -180.0
THROTTLE_COUNT, THROTTLE_COOLDOWN = 17, 10.0
MIN_RSSI_DEFAULT, MIN_RSSI_FLOOR = -90, 3

TIMEOUT, RETRIES, BACKOFF, DELAY = 12.0, 3, 0.6, 0.5
OUTLIER_CAP_M = 100.0

MAC = re.compile(r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$")
LOG = logging.getLogger("wifilocate")


class AppleError(Exception):
    def __init__(self, message: str, unknown: Sequence[str] = ()) -> None:
        super().__init__(message)
        self.unknown = list(unknown)


@dataclass(frozen=True)
class AccessPoint:
    bssid: str
    rssi: int | None = None
    channel: int | None = None
    ssid: str | None = None

    @classmethod
    def from_raw(
        cls,
        mac: bytes,
        rssi: int | None = None,
        channel: int | None = None,
        ssid: str | None = None,
    ) -> "AccessPoint":
        if len(mac) != 6:
            raise ValueError(f"mac must be 6 bytes, got {len(mac)}")
        return cls(bssid=":".join(f"{b:02x}" for b in mac), rssi=rssi, channel=channel, ssid=ssid)

    @property
    def location(self) -> bool:
        return MAC.match(self.bssid) is not None


@dataclass(frozen=True)
class Fix:
    bssid: str
    latitude: float
    longitude: float
    accuracy: float | None


@dataclass
class Location:
    latitude: float
    longitude: float
    accuracy: float | None
    confidence: float
    samples: int
    spread: float | None
    fixes: list[Fix]
    unknown: list[str]
    source: str
    throttled: bool
    requests: int

    def as_dict(self) -> dict[str, Any]:
        return {
            "location": {"lat": self.latitude, "lng": self.longitude},
            "accuracy": self.accuracy,
            "confidence": self.confidence,
            "samples": self.samples,
            "spread": self.spread,
            "source": self.source,
            "throttled": self.throttled,
            "requests": self.requests,
            "fixes": [
                {"bssid": f.bssid, "lat": f.latitude, "lng": f.longitude, "acc": f.accuracy}
                for f in self.fixes
            ],
            "unknown": self.unknown,
        }

    def to_json(self, **kw: Any) -> str:
        return json.dumps(self.as_dict(), **kw)

    def __str__(self) -> str:
        acc = f"±{self.accuracy:.0f}m" if self.accuracy is not None else "±?"
        return (
            f"{self.latitude:.7f}, {self.longitude:.7f} {acc} "
            f"conf={self.confidence:.2f} n={self.samples} src={self.source}"
        )


def norm(raw: str | bytes) -> str:
    if isinstance(raw, (bytes, bytearray)):
        if len(raw) == 6:
            return ":".join(f"{b:02x}" for b in raw)
        raw = bytes(raw).hex()
    text = str(raw)
    if re.fullmatch(r"[0-9a-fA-F]{1,2}([:.\-][0-9a-fA-F]{1,2}){5}", text):
        parts = re.split(r"[:.\-]", text)
        return ":".join(p.lower().zfill(2) for p in parts)
    hex12 = re.sub(r"[^0-9a-fA-F]", "", text)
    if len(hex12) != 12:
        raise ValueError(f"bad bssid: {raw!r}")
    return ":".join(hex12[i:i + 2].lower() for i in range(0, 12, 2))


def varint(v: int) -> bytes:
    out = bytearray()
    while True:
        b, v = v & 0x7F, v >> 7
        out.append(b | (0x80 if v else 0))
        if not v:
            return bytes(out)


def fstr(num: int, s: str | bytes) -> bytes:
    raw = s.encode() if isinstance(s, str) else s
    return varint((num << 3) | 2) + varint(len(raw)) + raw


def fvar(num: int, v: int) -> bytes:
    return varint(num << 3) + varint((v + (1 << 64)) if v < 0 else v)


def payload(bssids: Sequence[str], neighbours: bool = True) -> bytes:
    body = b"".join(fstr(2, fstr(1, b)) for b in bssids)
    return body + fvar(3, 0) + fvar(4, 0 if neighbours else 1)


def batches(bssids: Sequence[str], neighbours: bool = True) -> list[list[str]]:
    over = len(fvar(3, 0)) + len(fvar(4, 0 if neighbours else 1))
    out: list[list[str]] = []
    cur: list[str] = []
    size = over
    for b in bssids:
        cost = 4 + len(b)
        if cur and size + cost > MAX_PAYLOAD:
            out.append(cur)
            cur, size = [], over
        cur.append(b)
        size += cost
    if cur:
        out.append(cur)
    return out


def envelope(p: bytes) -> bytes:
    if len(p) > MAX_PAYLOAD:
        raise AppleError(f"payload {len(p)} > {MAX_PAYLOAD}")
    return (
        b"\x00\x01\x00\x05en_US\x00\x13com.apple.locationd"
        b"\x00\x0a8.1.12B411\x00\x00\x00\x01\x00\x00\x00"
        + bytes([len(p)])
        + p
    )


def pb_decode(buf: bytes) -> list[tuple[int, int, Any]]:
    out: list[tuple[int, int, Any]] = []
    i, n = 0, len(buf)
    while i < n:
        tag = shift = 0
        while True:
            if i >= n or shift > 35:
                return out
            b, i = buf[i], i + 1
            tag |= (b & 0x7F) << shift
            shift += 7
            if not b & 0x80:
                break
        num, wire = tag >> 3, tag & 7
        if wire == 0:
            v = shift = 0
            while True:
                if i >= n or shift > 63:
                    return out
                b, i = buf[i], i + 1
                v |= (b & 0x7F) << shift
                shift += 7
                if not b & 0x80:
                    break
            out.append((num, wire, v - (1 << 64) if v >= 1 << 63 else v))
        elif wire in (1, 5):
            size = 8 if wire == 1 else 4
            if i + size > n:
                return out
            out.append((num, wire, buf[i:i + size]))
            i += size
        elif wire == 2:
            ln = shift = 0
            while True:
                if i >= n or shift > 35:
                    return out
                b, i = buf[i], i + 1
                ln |= (b & 0x7F) << shift
                shift += 7
                if not b & 0x80:
                    break
            if ln < 0 or i + ln > n:
                return out
            out.append((num, wire, buf[i:i + ln]))
            i += ln
        else:
            return out
    return out


def parse_fixes(body: bytes) -> dict[str, Fix]:
    if body[:2] == b"\x1f\x8b":
        body = gzip.decompress(body)
    if len(body) < RES_HDR:
        raise AppleError(f"short response: {len(body)}B")
    fixes: dict[str, Fix] = {}
    for num, wire, dev in pb_decode(body[RES_HDR:]):
        if num != 2 or wire != 2:
            continue
        bssid = lat = lng = acc = None
        for sn, sw, sv in pb_decode(dev):
            if sn == 1 and sw == 2:
                bssid = sv.decode("utf-8", "replace")
            elif sn == 2 and sw == 2:
                for ln, lw, lv in pb_decode(sv):
                    if lw == 0 and ln in (1, 2, 3):
                        if ln == 1:
                            lat = lv
                        elif ln == 2:
                            lng = lv
                        else:
                            acc = lv
        if bssid is None or lat is None or lng is None:
            continue
        try:
            key = norm(bssid)
        except ValueError:
            continue
        if lat / SCALE == SENTINEL or lng / SCALE == SENTINEL or key in fixes:
            continue
        if acc is not None and not (0 <= acc <= 10000):
            acc = None
        fixes[key] = Fix(
            bssid=key,
            latitude=lat / SCALE,
            longitude=lng / SCALE,
            accuracy=float(acc) if acc is not None else None,
        )
    return fixes


def _haversine(a_lat: float, a_lng: float, b_lat: float, b_lng: float) -> float:
    r = 6371000.0
    p1, p2 = math.radians(a_lat), math.radians(b_lat)
    dlat = math.radians(b_lat - a_lat)
    dlng = math.radians(b_lng - a_lng)
    h = math.sin(dlat / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dlng / 2) ** 2
    return 2 * r * math.asin(math.sqrt(h))


def weighted_centroid(fixes: Sequence[Fix]) -> tuple[float, float]:
    if not fixes:
        raise AppleError("centroid of empty fix list")
    weights = [1.0 / (1.0 + (f.accuracy if f.accuracy is not None else 50.0) ** 2) for f in fixes]
    total = sum(weights)
    lat = sum(f.latitude * w for f, w in zip(fixes, weights)) / total
    lng = sum(f.longitude * w for f, w in zip(fixes, weights)) / total
    return lat, lng


def reject_outliers(fixes: Sequence[Fix]) -> list[Fix]:
    if len(fixes) < 3:
        return list(fixes)
    lats = sorted(f.latitude for f in fixes)
    lngs = sorted(f.longitude for f in fixes)
    lat, lng = lats[len(lats) // 2], lngs[len(lngs) // 2]
    accs = sorted(f.accuracy for f in fixes if f.accuracy is not None)
    med_acc = accs[len(accs) // 2] if accs else 50.0
    thr = max(OUTLIER_CAP_M, 3.0 * med_acc)
    kept = [f for f in fixes if _haversine(lat, lng, f.latitude, f.longitude) <= thr]
    return kept if kept else list(fixes)


def spread(fixes: Sequence[Fix]) -> float | None:
    if len(fixes) < 2:
        return None
    return max(
        _haversine(fixes[i].latitude, fixes[i].longitude, fixes[j].latitude, fixes[j].longitude)
        for i in range(len(fixes))
        for j in range(i + 1, len(fixes))
    )


def confidence(fixes: Sequence[Fix], spread_m: float | None) -> float:
    if not fixes:
        return 0.0
    score = 0.3 + min(0.4, 0.1 * (len(fixes) - 1))
    if spread_m is not None:
        score += min(0.3, 0.3 * (1.0 - min(spread_m, 100.0) / 100.0))
    return max(0.0, min(1.0, score))


def resolve_endpoint(endpoint: str) -> str:
    url = ENDPOINTS.get(endpoint, endpoint)
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != "https" or not parsed.hostname:
        raise ValueError(f"bad endpoint: {endpoint!r}")
    return url


class AppleClient:
    def __init__(
        self,
        endpoint: str = DEFAULT_ENDPOINT,
        *,
        timeout: float = TIMEOUT,
        retries: int = RETRIES,
        delay: float = DELAY,
        neighbours: bool = True,
    ) -> None:
        self.endpoint = endpoint
        self.url = resolve_endpoint(endpoint)
        self.timeout = timeout
        self.retries = max(1, retries)
        self.delay = delay
        self.neighbours = neighbours
        self.requests = 0
        self.throttled_until = 0.0
        self._conn: http.client.HTTPSConnection | None = None
        self._ctx = ssl.create_default_context()
        parsed = urllib.parse.urlsplit(self.url)
        self._host = parsed.hostname or ""
        self._path = parsed.path or "/clls/wloc"

    @property
    def throttled(self) -> bool:
        return time.monotonic() < self.throttled_until

    def __enter__(self) -> "AppleClient":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()

    def _connect(self) -> http.client.HTTPSConnection:
        self.close()
        self._conn = http.client.HTTPSConnection(
            self._host, 443, timeout=self.timeout, context=self._ctx
        )
        return self._conn

    @property
    def conn(self) -> http.client.HTTPSConnection:
        return self._conn or self._connect()

    def close(self) -> None:
        if self._conn:
            try:
                self._conn.close()
            except OSError:
                pass
            self._conn = None

    def _pace(self) -> None:
        if self.delay <= 0:
            return
        wait = self.delay - (time.monotonic() - getattr(self, "_last", 0.0))
        if wait > 0:
            time.sleep(wait)

    def _use_neighbours(self) -> bool:
        return self.neighbours and not self.throttled

    def post(self, body: bytes) -> bytes:
        last: Exception | None = None
        for attempt in range(self.retries):
            self._pace()
            try:
                conn = self.conn
                self._last = time.monotonic()
                self.requests += 1
                conn.request("POST", self._path, body=body, headers=HEADERS)
                resp = conn.getresponse()
                data = resp.read()
                if resp.getheader("Connection", "").lower() == "close" or resp.version < 11:
                    self.close()
                if resp.status == 200:
                    if resp.getheader("Content-Encoding", "").lower() == "gzip":
                        data = gzip.decompress(data)
                    return data
                if resp.status == 429:
                    last = AppleError("rate limited")
                    wait = BACKOFF * (2 ** attempt)
                    try:
                        wait = max(wait, float(resp.getheader("Retry-After", "0")))
                    except ValueError:
                        pass
                    time.sleep(wait)
                    continue
                if resp.status >= 500 and attempt < self.retries - 1:
                    time.sleep(BACKOFF * (2 ** attempt))
                    continue
                raise AppleError(f"HTTP {resp.status}: {data[:120]!r}")
            except AppleError:
                self.close()
                raise
            except (OSError, http.client.HTTPException) as exc:
                last = exc
                self.close()
                if attempt < self.retries - 1:
                    time.sleep(BACKOFF * (2 ** attempt))
                    continue
        self.close()
        raise AppleError(f"failed after {self.retries} tries: {last}")

    def query(self, bssids: Sequence[str]) -> dict[str, Fix]:
        out: dict[str, Fix] = {}
        if not bssids:
            return out
        try:
            for batch in batches(bssids, self.neighbours):
                use_nb = self._use_neighbours()
                out.update(parse_fixes(self.post(envelope(payload(batch, use_nb)))))
                if len(out) >= THROTTLE_COUNT:
                    self.throttled_until = time.monotonic() + THROTTLE_COOLDOWN
                    LOG.debug("throttle signal: %d fixes, neighbours off %.0fs", len(out), THROTTLE_COOLDOWN)
        finally:
            self.close()
        return out


def scan(timeout: float = 20.0) -> list[AccessPoint]:
    try:
        proc = subprocess.run(
            ["netsh", "wlan", "show", "networks", "mode=bssid"],
            capture_output=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        raise AppleError(f"netsh: {exc}") from exc
    if proc.returncode != 0:
        raise AppleError(f"netsh exit {proc.returncode}")

    aps: list[AccessPoint] = []
    ssid: str | None = None
    cur: dict[str, Any] | None = None

    def flush() -> None:
        nonlocal cur
        if cur and cur.get("mac"):
            try:
                bssid = norm(str(cur["mac"]))
            except ValueError:
                bssid = None
            if bssid:
                pct = cur.get("sig")
                rssi = None if pct is None else max(-100, min(-50, round(-100 + pct * 0.6)))
                aps.append(AccessPoint(bssid=bssid, rssi=rssi, channel=cur.get("ch"), ssid=ssid))
        cur = None

    for line in proc.stdout.splitlines():
        s = line.strip()
        if m := re.match(r"^SSID\s+\d+\s*:\s*(.*)$", s):
            flush()
            ssid = m.group(1).strip() or None
        elif m := re.match(r"^BSSID\s+\d+\s*:\s*(\S+)$", s, re.I):
            flush()
            cur = {"mac": m.group(1)}
        elif cur is not None and (m := re.match(r"^Signal\s*:\s*(\d+)\s*%", s, re.I)):
            cur["sig"] = int(m.group(1))
        elif cur is not None and (m := re.match(r"^Channel\s*:\s*(\d+)$", s, re.I)):
            cur["ch"] = int(m.group(1))
    flush()

    seen: set[str] = set()
    return [a for a in aps if not (a.bssid in seen or seen.add(a.bssid))]


def _coerce(value: Any) -> list[AccessPoint] | None:
    if value is None:
        return None
    if isinstance(value, (str, bytes, AccessPoint)):
        value = [value]
    out: list[AccessPoint] = []
    for item in value:
        if isinstance(item, AccessPoint):
            ap = item
        elif isinstance(item, (str, bytes)):
            ap = AccessPoint(bssid=norm(item))
        else:
            raise TypeError(f"unsupported target item: {type(item).__name__}")
        if ap.bssid not in {x.bssid for x in out}:
            out.append(ap)
    return out


class HuyLocationAlgorithm:
    def __init__(
        self,
        *,
        endpoint: str = DEFAULT_ENDPOINT,
        fallback: bool = True,
        timeout: float = TIMEOUT,
        retries: int = RETRIES,
        delay: float = DELAY,
        neighbours: bool = True,
        min_rssi: int | None = None,
        refine: bool = True,
    ) -> None:
        self.endpoint = endpoint
        self.fallback = fallback
        self.timeout = timeout
        self.retries = retries
        self.delay = delay
        self.neighbours = neighbours
        self.min_rssi = min_rssi
        self.refine = refine

    def __enter__(self) -> "HuyLocationAlgorithm":
        return self

    def __exit__(self, *exc: Any) -> None:
        pass

    @staticmethod
    def _filter(aps: list[AccessPoint], min_rssi: int | None) -> list[AccessPoint]:
        floor = MIN_RSSI_DEFAULT if min_rssi is None else min_rssi
        strong = [ap for ap in aps if ap.rssi is None or ap.rssi >= floor]
        return strong if len(strong) >= MIN_RSSI_FLOOR else aps

    def _client(self, endpoint: str) -> AppleClient:
        return AppleClient(
            endpoint,
            timeout=self.timeout,
            retries=self.retries,
            delay=self.delay,
            neighbours=self.neighbours,
        )

    def geolocate(
        self,
        wifi_access_points: Any = None,
        *,
        min_rssi: int | None = None,
        neighbours: bool | None = None,
        endpoint: str | None = None,
    ) -> Location:
        aps = _coerce(wifi_access_points)
        if aps is None:
            aps = scan()
        if not aps:
            raise AppleError("no access points")
        aps = self._filter(aps, self.min_rssi if min_rssi is None else min_rssi)

        bssids = [ap.bssid for ap in aps]
        primary = endpoint or self.endpoint
        if neighbours is not None:
            saved, self.neighbours = self.neighbours, neighbours
        else:
            saved = None

        try:
            client = self._client(primary)
            try:
                fixes_by_bssid = client.query(bssids)
                source, requests, throttled = client.endpoint, client.requests, client.throttled
            except AppleError:
                if not self.fallback or resolve_endpoint(primary) != ENDPOINTS["apple"]:
                    raise
                LOG.debug("primary endpoint failed, falling back to grapheneos")
                client = self._client("grapheneos")
                fixes_by_bssid = client.query(bssids)
                source, requests, throttled = client.endpoint, client.requests, client.throttled
        finally:
            if saved is not None:
                self.neighbours = saved

        if not fixes_by_bssid:
            raise AppleError("no access points resolved", unknown=bssids)

        fixes = list(fixes_by_bssid.values())
        unknown = [b for b in bssids if b not in fixes_by_bssid]

        if self.refine:
            fixes = reject_outliers(fixes)
            latitude, longitude = weighted_centroid(fixes)
            spread_m = spread(fixes)
        else:
            latitude, longitude = fixes[0].latitude, fixes[0].longitude
            spread_m = None

        accs = [f.accuracy for f in fixes if f.accuracy is not None]
        accuracy: float | None = max(accs) if accs else None
        if spread_m is not None:
            accuracy = max(accuracy or 0.0, spread_m / 2.0)

        return Location(
            latitude=latitude,
            longitude=longitude,
            accuracy=accuracy,
            confidence=confidence(fixes, spread_m),
            samples=len(fixes),
            spread=spread_m,
            fixes=fixes,
            unknown=unknown,
            source=source,
            throttled=throttled,
            requests=requests,
        )


def geolocate(wifi_access_points: Any = None, **options: Any) -> Location:
    with HuyLocationAlgorithm(**options) as geo:
        return geo.geolocate(wifi_access_points)


__all__ = [
    "AccessPoint",
    "Fix",
    "Location",
    "AppleError",
    "AppleClient",
    "HuyLocationAlgorithm",
    "geolocate",
    "scan",
    "norm",
    "ENDPOINTS",
    "DEFAULT_ENDPOINT",
    "VERSION",
]


def _smoke() -> int:
    checks: list[tuple[str, bool, str]] = []

    p = payload(["aa:bb:cc:dd:ee:ff"])
    env = envelope(p)
    bb = batches([f"aa:bb:cc:dd:ee:{i:02x}" for i in range(40)])
    ok = (
        len(env) == ENVELOPE_LEN + len(p)
        and env[ENVELOPE_LEN - 1] == len(p)
        and all(len(payload(b)) <= MAX_PAYLOAD for b in bb)
        and norm("24:B:2B:11:5D:D9") == "24:0b:2b:11:5d:d9"
        and norm(b"\x24\x0b\x2b\x11\x5d\xd9") == "24:0b:2b:11:5d:d9"
    )
    checks.append(("codec", ok, f"env={len(env)} chunks={len(bb)}"))

    synth = (
        b"\x00" * RES_HDR
        + fstr(2, fstr(1, "aa:bb:cc:dd:ee:ff") + fstr(
            2, fvar(1, 1601742172) + fvar(2, 10820785522) + fvar(3, 25)))
    )
    fixes = parse_fixes(synth)
    f = fixes.get("aa:bb:cc:dd:ee:ff")
    ok = (
        f is not None
        and abs(f.latitude - 16.01742172) < 1e-6
        and abs(f.longitude - 108.20785522) < 1e-6
        and f.accuracy == 25.0
    )
    checks.append(("parse", ok, f"fix={f}"))

    two = [
        Fix("aa:bb:cc:dd:ee:01", 16.0174, 108.2079, 20.0),
        Fix("aa:bb:cc:dd:ee:02", 16.0175, 108.2080, 30.0),
        Fix("aa:bb:cc:dd:ee:03", 16.0500, 108.2500, 25.0),
    ]
    kept = reject_outliers(two)
    lat, lng = weighted_centroid(kept)
    conf = confidence(kept, spread(kept))
    ok = len(kept) == 2 and lat < 16.02 and 0.0 < conf <= 1.0
    checks.append(("algo", ok, f"kept={len(kept)} lat={lat:.4f} conf={conf:.2f}"))

    try:
        loc = geolocate()
        checks.append(("live", True, str(loc)))
    except AppleError as exc:
        checks.append(("live", False, str(exc)))

    failed = 0
    for name, good, info in checks:
        print(f"{'PASS' if good else 'FAIL':4}  {name:6}  {info}")
        failed += not good
    return 1 if failed else 0


if __name__ == "__main__":
    logging.basicConfig(level=logging.WARNING)
    try:
        sys.exit(_smoke())
    except KeyboardInterrupt:
        sys.exit(130)
    except Exception:
        traceback.print_exc()
        sys.exit(2)
