# wifilocate

Single-file Python library that turns Wi-Fi BSSIDs into geographic coordinates by speaking the
same binary protocol as Apple's `locationd`. No API key, no dependencies, stdlib only.

```
BSSID list  →  Apple WLOC (gs-loc.apple.com)  →  lat/lng ± accuracy
```

> **Unofficial API.** `gs-loc.apple.com/clls/wloc` is a private, undocumented endpoint used by
> iOS/macOS for Wi-Fi positioning. This project is for research and educational use. Query only
> networks you are authorized to look up, respect the `_nomap` SSID opt-out, and expect results
> to be stale or imprecise.

## Features

- **Zero dependencies**: Python ≥ 3.9 stdlib only (`http.client`, `ssl`, `gzip`)
- **One file**: drop `wifilocate.py` into any project
- **No API key**: speaks Apple's protobuf-in-envelope protocol directly
- **Auto mode**: scans nearby networks with `netsh` (Windows) when you pass no BSSIDs
- **Batching**: greedy chunking to the 255-byte payload limit, keep-alive connections
- **Hardening**: RSSI filtering, median-based outlier rejection, HTTP 429 backoff,
  throttle-aware neighbour suppression, automatic fallback endpoint
- **Portable core**: codec and algorithm layers perform no IO: a 1:1 port target for C++/ESP32

## Quickstart

```python
from wifilocate import HuyLocationAlgorithm

geo = HuyLocationAlgorithm()

loc = geo.geolocate()                                   # full auto: scan + query
loc = geo.geolocate(wifi_access_points="24:0b:2b:11:5d:d9")
loc = geo.geolocate(wifi_access_points=["aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66"])

print(loc)                    # 16.0173944, 108.2078762 ±38m conf=0.78 n=24 src=apple
print(loc.latitude, loc.longitude, loc.accuracy, loc.confidence)
```

One-shot sugar:

```python
from wifilocate import geolocate
loc = geolocate()   # scans and queries in one call
```

Feed it anything: a string, raw 6 bytes from an ESP32 `wifi_ap_record_t`, or `AccessPoint` objects:

```python
from wifilocate import geolocate, AccessPoint

geolocate("24:0b:2b:11:5d:d9")
geolocate([b"\x24\x0b\x2b\x11\x5d\xd9", "aa:bb:cc:dd:ee:ff"])
geolocate(AccessPoint.from_raw(mac6_bytes, rssi=-55, channel=153, ssid="MyWifi"))
```

Run the built-in smoke test (codec + parser + algorithm + live query):

```console
$ python wifilocate.py
PASS  codec   env=75 chunks=4
PASS  parse   fix=Fix(bssid='aa:bb:cc:dd:ee:ff', latitude=16.01742172, longitude=108.20785522, accuracy=25.0)
PASS  algo    kept=2 lat=16.0174 conf=0.65
PASS  live    16.0171103, 108.2078327 ±94m conf=0.70 n=98 src=apple
```

## Accuracy (example run)

Numbers below are from a representative session; coordinates are redacted.

| Mode                       | Error vs OS ground truth | Reported acc | Fixes | Wall time |
| -------------------------- | ------------------------ | ------------ | ----- | --------- |
| `neighbours=False` (tight) | ~10 m                    | ±38 m        | ~24   | 2.3 s     |
| `neighbours=True` (dump)   | ~40 m                    | ±94 m        | ~98   | 2.3 s     |

`neighbours=False` queries only the BSSIDs you asked for (fast, tight).
`neighbours=True` also asks Apple to return surrounding access points (~100 extra fixes),
which widens the spread but adds context. Ground truth from the OS location API (±135 m).

## Documentation

| Document                                                       | What it covers                                                              |
| -------------------------------------------------------------- | --------------------------------------------------------------------------- |
| [docs/REVERSE_ENGINEERING.md](docs/REVERSE_ENGINEERING.md)     | How the endpoint was found and how the binary protocol works, byte by byte   |
| [docs/ALGORITHM.md](docs/ALGORITHM.md)                          | Position pipeline: filtering, outlier rejection, weighting, confidence        |
| [docs/API.md](docs/API.md)                                      | Full API reference, `Location` JSON schema, error handling                   |
| [docs/PORTING.md](docs/PORTING.md)                              | C++/ESP32 porting checklist with golden test vectors                         |

## How it works (short version)

1. **Scan** nearby BSSIDs (Windows `netsh`, or your own list).
2. **Encode** each batch of BSSIDs as a protobuf message wrapped in Apple's fixed 50-byte
   envelope, POST it to `https://gs-loc.apple.com/clls/wloc` pretending to be `locationd`.
3. **Decode** the binary response: one location per BSSID, fixed-point `×1e8`, with a `-180`
   sentinel for unknown networks.
4. **Aggregate** with median-outlier rejection and an accuracy-weighted centroid
   (`w = 1/(1 + acc²)`), then report accuracy, spread, and confidence.

The endpoint and wire format came out of real device traffic; the full walkthrough lives in
[docs/REVERSE_ENGINEERING.md](docs/REVERSE_ENGINEERING.md).

## License

[MIT](LICENSE)
