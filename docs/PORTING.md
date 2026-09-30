# Porting to C++ / ESP32

`wifilocate.py` is structured so the binary protocol and the math port 1:1, while the
transport layer gets swapped for whatever the target platform provides.

```
┌─────────────────────────────────────────────┐  IO: swap this
│ AppleClient (http.client/ssl) + scan (netsh)│  ──▶ esp_http_client / mbedtls / lwIP
├─────────────────────────────────────────────┤  pure: port as-is
│ codec: norm, varint, fstr, fvar, payload,   │  ──▶ wloc_codec.{h,cpp}
│        batches, envelope, pb_decode,        │
│        parse_fixes                          │
├─────────────────────────────────────────────┤  pure: port as-is
│ algo: weighted_centroid, reject_outliers,   │  ──▶ wloc_algo.{h,cpp}
│       spread, confidence, _haversine        │
└─────────────────────────────────────────────┘
```

**Rule of thumb:** if a function touches `socket`, `file`, `subprocess`, or `time.sleep`,
it belongs to the platform layer. Everything else is a direct translation.

## Checklist

### codec (no IO, no allocation beyond output buffers)

- [ ] `varint(u64)`: 7-bit groups, `0x80` continuation, little-endian group order
- [ ] `fstr(field, bytes)`: tag `(field<<3)|2`, length varint, payload
- [ ] `fvar(field, i64)`: tag `(field<<3)|0`; negative values: add `2^64` before varint
      (int64 two's complement → 10 bytes)
- [ ] `payload(bssids, neighbours)`: `field2{field1=bssid}` × N, then `field3=0`,
      `field4=0|1` (0 = return neighbours)
- [ ] `batches(bssids, neighbours)`: greedy: `size += 4 + len(bssid)`, flush when
      `size + cost > 255`, initial size = overhead of field3+field4 (4 bytes)
- [ ] `envelope(payload)`: fixed 50-byte prefix (constants below) + 1 length byte
- [ ] `pb_decode(buf)`: generic protobuf walker: wire type 0 (varint, signed via
      `>= 2^63 ? v - 2^64 : v`), 2 (length-delimited), 1/5 (fixed, skip), anything else
      = stop
- [ ] `parse_fixes(body)`: gunzip if magic `1f 8b`; skip 10-byte header; walk field-2
      devices; inner field1 = BSSID string, field2 = location message (fields 1/2/3 =
      lat/lng/acc); `/1e8`; drop `-180` sentinel; clamp accuracy to `[0,10000]`;
      normalize + dedupe BSSIDs
- [ ] `norm(bssid)`: lowercase, colon-separated, zero-padded octets; accept 6 raw bytes
      and bare 12-hex strings

### algorithm (no IO)

- [ ] `_haversine(lat1, lng1, lat2, lng2)`: R = 6 371 000 m
- [ ] `reject_outliers`: **median** lat/lng as center (not mean!), threshold
      `max(100, 3 × median_accuracy)`, fall back to full list if all rejected
- [ ] `weighted_centroid`: `w = 1/(1 + acc²)`, acc defaults to 50 when null
- [ ] `spread`: max pairwise haversine distance
- [ ] `confidence`: `0.3 + min(0.4, 0.1×(n−1)) + min(0.3, 0.3×(1−min(spread,100)/100))`
- [ ] `accuracy`: `max(max_acc, spread/2)`

### transport (platform-specific)

- [ ] HTTPS POST, keep-alive across batches, 0.5 s min spacing
- [ ] Headers exactly as in RE doc §4.1 (UA, content-type, accept-encoding)
- [ ] gzip decode (mandatory: some responses compress regardless of headers)
- [ ] Retries: 3, exponential backoff 0.6/1.2/2.4 s, honor `Retry-After` on 429
- [ ] Throttle: ≥17 fixes → set `num_wifi_results=1` for next 10 s (suppress, don't sleep)
- [ ] Fallback: primary fails → retry once against
      `https://gs-loc.apple.grapheneos.org/clls/wloc`
- [ ] TLS: system CA store (ESP32: `esp_crt_bundle_attach`)
- [ ] Timeout 12 s per request

### ESP32-specific notes

- Scan via `esp_wifi_scan` + `esp_wifi_ap_record_t.bssid` / `rssi` (true dBm, so skip the
  netsh %-conversion entirely); feed `AccessPoint.from_raw(mac6, rssi)` equivalents.
- Heap: batch payloads ≤ 255 B, response for a neighbours query ≈ 8–15 KB compressed /
  ~60 KB raw, so budget a 64 KB read buffer or parse incrementally from the socket.
- Non-blocking: run the query on a worker task; `Location` assembly is microseconds.

---

## Golden test vectors

Assert these byte-for-byte: they are what the Python implementation produces and what the
live server accepts.

### 1. Varint encodings

| Value | Encoded hex |
| --- | --- |
| `25` | `19` |
| `1601742172` | `dccae2fb05` |
| `10820785522` | `f2aae0a728` |
| `-180` (as int64, i.e. `2^64 − 180`) | `ccfeffffffffffffff01` |

### 2. Request payload: one BSSID, neighbours on

Input: `["aa:bb:cc:dd:ee:ff"]`, `neighbours=True` (`field4 = 0`)

```
12130a1161613a62623a63633a64643a65653a666618002000
```

Decoded structure:

```
12 13                field2 (Device), LEN=19
  0a 11              field1 (bssid), LEN=17
    "aa:bb:cc:dd:ee:ff"
18 00                field3 = 0
20 00                field4 = 0  (return neighbours)
```

Same input with `neighbours=False`: last byte becomes `01` (`2001`).

### 3. Full request body (envelope + payload)

```
00010005656e5f55530013636f6d2e6170706c652e6c6f636174696f6e64000a
382e312e3132423431310000000100000019
12130a1161613a62623a63633a64643a65653a666618002000
```

- total length: **75 bytes** (50 envelope + 25 payload)
- byte at offset 49: `19` (= 25 = payload length)

### 4. Response parsing

Synthetic response (10-byte header + protobuf):

```
00000000000000000000
12230a1161613a62623a63633a64643a65653a6666120e08dccae2fb0510f2aae0a7281819
```

Expected single fix:

```
bssid     = "aa:bb:cc:dd:ee:ff"
latitude  = 1601742172 / 1e8 = 16.01742172
longitude = 10820785522 / 1e8 = 108.20785522
accuracy  = 25.0
```

Sentinel handling: a device whose lat/lng varints decode to `-180` must be **dropped**.

### 5. Batching

40 BSSIDs `aa:bb:cc:dd:ee:00` … `aa:bb:cc:dd:ee:27`, neighbours on:

```
batch sizes = [11, 11, 11, 7]
every encoded payload ≤ 255 bytes
```

(Rule: 4-byte overhead + 21 bytes per `"aa:bb:cc:dd:ee:xx"` entry → 11 entries fill
`4 + 11×21 = 235`, the 12th would make 256 > 255.)

### 6. BSSID normalization

| Input | Output |
| --- | --- |
| `"24:0B:2B:11:5D:D9"` | `"24:0b:2b:11:5d:d9"` |
| `"24:B:2B:11:5D:D9"` | `"24:0b:2b:11:5d:d9"` |
| `"240b2b115dd9"` | `"24:0b:2b:11:5d:d9"` |
| `b"\x24\x0b\x2b\x11\x5d\xd9"` | `"24:0b:2b:11:5d:d9"` |
| `"xyz"` | error (`ValueError` / `std::invalid_argument`) |

### 7. Algorithm

Input fixes:

```
A: (16.0174, 108.2079) acc=20
B: (16.0175, 108.2080) acc=30
C: (16.0500, 108.2500) acc=25     ← ~4.7 km away, must be rejected
```

Expected (full double precision, Python reference):

```
kept     = [A, B]
centroid = (16.01743079877112, 108.20793079877112)
spread   = 15.42311142271501
confidence = 0.653730665731855
```

Tolerance for a port: `1e-7` on coordinates, `1e-3` on spread/confidence.

---

## Verification

After porting, run in order:

1. **Codec:** all golden vectors above, byte-for-byte.
2. **Parser:** vector #4 + a real captured response if you have one.
3. **Live:** single-BSSID query against the real endpoint; expect HTTP 200 and a fix near
   the AP's true location (±50 m), or a clean sentinel drop for an unknown BSSID.
4. **End-to-end:** full scan → query → centroid; compare against the Python
   implementation on the same BSSID set; positions should agree to < 1 m (identical math).
