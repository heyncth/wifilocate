# API Reference

`wifilocate.py` — single file, stdlib only, Python ≥ 3.9.

```python
from wifilocate import HuyLocationAlgorithm, geolocate, AccessPoint, AppleError
```

Everything is exported through `__all__`:

```python
["AccessPoint", "Fix", "Location", "AppleError", "AppleClient",
 "HuyLocationAlgorithm", "geolocate", "scan", "norm", "ENDPOINTS",
 "DEFAULT_ENDPOINT", "VERSION"]
```

Importing the module has **no side effects** (no network, no subprocess). Running it as a
script (`python wifilocate.py`) executes the smoke test.

---

## `HuyLocationAlgorithm`

Main entry point. Owns configuration; `geolocate()` runs one full lookup.

```python
HuyLocationAlgorithm(
    *,
    endpoint: str = "apple",       # "apple" | "grapheneos" | full https:// URL
    fallback: bool = True,         # auto-fallback to grapheneos if primary (apple) fails
    timeout: float = 12.0,         # seconds per HTTP request
    retries: int = 3,              # attempts per request (429/5xx/network)
    delay: float = 0.5,            # min spacing between requests on one connection
    neighbours: bool = True,       # num_wifi_results=0: also return ~100 surrounding APs
    min_rssi: int | None = None,   # RSSI floor (default -90 when None)
    refine: bool = True,           # outlier rejection + weighted centroid
)
```

Context manager (no-op but allowed): `with HuyLocationAlgorithm() as geo: ...`

### `.geolocate(wifi_access_points=None, *, min_rssi=None, neighbours=None, endpoint=None) -> Location`

| Parameter | Type | Meaning |
| --- | --- | --- |
| `wifi_access_points` | see accepted forms below | `None` → auto-scan via `netsh` (Windows) |
| `min_rssi` | `int \| None` | per-call override of the RSSI floor |
| `neighbours` | `bool \| None` | per-call override; restored after the call |
| `endpoint` | `str \| None` | per-call override of the endpoint |

**Accepted `wifi_access_points` forms:**

```python
None                                        # auto-scan
"24:0b:2b:11:5d:d9"                         # single string
b"\x24\x0b\x2b\x11\x5d\xd9"                 # single 6-byte MAC (ESP32-friendly)
["aa:bb:...", "11:22:...", b"\x01\x02..."]  # mixed list of strings/bytes
AccessPoint(...)                            # single object
[AccessPoint(...), AccessPoint(...)]        # list of objects
```

Duplicates are removed (by normalized BSSID), order preserved.

**Raises `AppleError` when:**

| Message | Cause |
| --- | --- |
| `no access points` | scan returned nothing / empty input list |
| `no access points resolved` | Apple answered but none of your BSSIDs exist in its database — `exc.unknown` lists them |
| `rate limited` | HTTP 429 persisted through all retries |
| `failed after N tries: ...` | network/TLS failures through all retries |
| `HTTP <status>: ...` | any other non-200 response |

**Example:**

```python
geo = HuyLocationAlgorithm(neighbours=False, min_rssi=-85)
try:
    loc = geo.geolocate()
except AppleError as e:
    print("failed:", e, "unknown bssids:", e.unknown)
else:
    print(f"{loc.latitude:.7f}, {loc.longitude:.7f} ±{loc.accuracy}m conf={loc.confidence}")
```

---

## `geolocate(...)` — module-level one-shot

```python
from wifilocate import geolocate
loc = geolocate()                                  # scan + query
loc = geolocate("24:0b:2b:11:5d:d9")               # explicit BSSID
loc = geolocate(aps, neighbours=False, endpoint="grapheneos")  # **options forwarded
```

Signature: `geolocate(wifi_access_points=None, **options)` where `**options` are exactly
the `HuyLocationAlgorithm` constructor keywords. Creates a client, runs one query, closes.

---

## `Location`

Returned by `geolocate()`. Mutable dataclass.

| Field | Type | Meaning |
| --- | --- | --- |
| `latitude` | `float` | degrees (weighted centroid, or first fix if `refine=False`) |
| `longitude` | `float` | degrees |
| `accuracy` | `float \| None` | metres, `max(worst fix accuracy, spread/2)` |
| `confidence` | `float` | 0.0–1.0 evidence score (see ALGORITHM.md §6) |
| `samples` | `int` | number of fixes used |
| `spread` | `float \| None` | max pairwise distance between fixes (m); `None` if < 2 |
| `fixes` | `list[Fix]` | all accepted per-BSSID fixes |
| `unknown` | `list[str]` | requested BSSIDs Apple did not know |
| `source` | `str` | endpoint that answered (`"apple"` / `"grapheneos"` / full URL) |
| `throttled` | `bool` | a throttle signal was seen during the query (see RE §7) |
| `requests` | `int` | how many HTTP requests were made |

**Methods:**

```python
loc.as_dict()                  # → dict (same structure as JSON below)
loc.to_json(indent=None, **kw) # → str; kwargs pass to json.dumps
str(loc)                       # "16.0173944, 108.2078762 ±38m conf=0.78 n=24 src=apple"
```

**JSON schema (`to_json`):**

```json
{
  "location":  { "lat": 16.0173944, "lng": 108.2078762 },
  "accuracy":  38.1,
  "confidence": 0.78,
  "samples":   24,
  "spread":    76.2,
  "source":    "apple",
  "throttled": false,
  "requests":  2,
  "fixes": [
    { "bssid": "24:0b:2b:11:5d:d9", "lat": 16.0174, "lng": 108.2079, "acc": 25.0 }
  ],
  "unknown": ["de:ad:be:ef:00:01"]
}
```

`accuracy`/`spread` may be `null`; `acc` inside `fixes` may be `null` when Apple omitted it.

---

## `Fix`

Immutable per-BSSID result.

```python
Fix(bssid: str, latitude: float, longitude: float, accuracy: float | None)
```

---

## `AccessPoint`

Immutable input record.

```python
AccessPoint(bssid: str, rssi: int | None = None,
            channel: int | None = None, ssid: str | None = None)
```

- `AccessPoint.from_raw(mac: bytes, rssi=None, channel=None, ssid=None) -> AccessPoint`
  — build from a 6-byte MAC (`len(mac)` must be 6, else `ValueError`).
- `.location -> bool` — `True` if `bssid` matches the canonical MAC pattern.
- `rssi`/`channel`/`ssid` are informational: only `rssi` affects filtering; the wire
  protocol carries BSSID only.

---

## `AppleClient`

Low-level client (transport + codec only — no centroid logic). Connection is opened lazily,
closed after `query()` or by `close()` / context exit.

```python
AppleClient(
    endpoint: str = "apple",
    *, timeout: float = 12.0, retries: int = 3,
    delay: float = 0.5, neighbours: bool = True,
)
```

| Member | Type | Meaning |
| --- | --- | --- |
| `.query(bssids: Sequence[str]) -> dict[str, Fix]` | method | batched query; keys are normalized BSSIDs. **Raises `AppleError`.** |
| `.post(body: bytes) -> bytes` | method | single POST with retry/backoff; returns decompressed body |
| `.requests` | `int` | HTTP request counter |
| `.throttled` | `bool` | throttle window active (≥ 17 fixes seen in last 10 s) |
| `.endpoint` / `.url` | `str` | configured endpoint name / resolved URL |
| `.close()` | method | drop the TLS connection |
| `with AppleClient() as c:` | ctx | closes on exit |

```python
from wifilocate import AppleClient
with AppleClient(neighbours=False) as c:
    fixes = c.query(["24:0b:2b:11:5d:d9"])
    print(c.requests, len(fixes))
```

---

## `scan(timeout=20.0) -> list[AccessPoint]`

Windows-only Wi-Fi scan via `netsh wlan show networks mode=bssid`.

- Parses `SSID` / `BSSID` / `Signal` / `Channel`; dedupes by BSSID (first wins).
- Signal % converted to approximate dBm: `max(-100, min(-50, round(-100 + pct × 0.6)))`.
- Raises `AppleError` on `netsh` failure/timeout. On other platforms, supply BSSIDs
  yourself.

---

## `norm(raw) -> str`

Normalize any BSSID representation to canonical `aa:bb:cc:dd:ee:ff`:

| Input | Output |
| --- | --- |
| `"24:0B:2B:11:5D:D9"` | `"24:0b:2b:11:5d:d9"` |
| `"24:B:2B:11:5D:D9"` (single-digit octets) | `"24:0b:2b:11:5d:d9"` |
| `"240b2b115dd9"` | `"24:0b:2b:11:5d:d9"` |
| `"24-0b-2b-11-5d-d9"` / `"24.0b...."` | `"24:0b:2b:11:5d:d9"` |
| `b"\x24\x0b\x2b\x11\x5d\xd9"` (6 bytes) | `"24:0b:2b:11:5d:d9"` |

**Raises `ValueError`** if the input cannot be a MAC (not 12 hex digits after stripping).

---

## Constants

| Name | Value | Meaning |
| --- | --- | --- |
| `VERSION` | `"3.0.0"` | library version |
| `ENDPOINTS` | `{"apple": ..., "grapheneos": ...}` | name → URL map |
| `DEFAULT_ENDPOINT` | `"apple"` | default endpoint name |

Internal tuning constants (codec limits, throttle, retry) live at module top as
`ENVELOPE_LEN`, `MAX_PAYLOAD`, `SCALE`, `THROTTLE_*`, `TIMEOUT`, `RETRIES`, `BACKOFF`,
`DELAY`, `MIN_RSSI_*`, `OUTLIER_CAP_M` — documented in RE/ALGORITHM docs rather than here.

---

## Smoke test

```console
$ python wifilocate.py
PASS  codec   env=75 chunks=4
PASS  parse   fix=Fix(bssid='aa:bb:cc:dd:ee:ff', latitude=16.01742172, longitude=108.20785522, accuracy=25.0)
PASS  algo    kept=2 lat=16.0174 conf=0.65
PASS  live    16.0171103, 108.2078327 ±94m conf=0.70 n=98 src=apple
```

Exit code `0` = all pass (the `live` check requires network access). Structure and the
golden vectors behind `codec`/`parse` are in [PORTING.md](PORTING.md).
