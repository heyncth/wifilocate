# Reverse Engineering Apple's WLOC Service

This document explains how the Wi-Fi positioning endpoint was discovered, how its wire format
was reverse engineered from device traffic, and how the binary protocol was reimplemented
without any official schema.

- **Endpoint:** `https://gs-loc.apple.com/clls/wloc`
- **Protocol:** HTTPS POST, custom 50-byte binary envelope wrapping a Protocol Buffers message
- **Client:** `locationd` (the daemon behind CoreLocation on iOS/macOS)
- **Status:** private, undocumented, no API key, no auth — but also no stability guarantees

Most overviews of "Wi-Fi geolocation APIs" stop at REST services with a JSON body. Apple's
service is different: the body is a hand-rolled envelope around a binary protobuf message,
the `Content-Type` header actively lies about the format, and no public schema exists.
Getting a first response requires capturing real device traffic and decoding the format
by inspection. That is what this document describes.

---

## 1. Finding the endpoint

The endpoint is not published anywhere. It has to be observed from a real iOS/macOS device
while it performs Wi-Fi positioning. Two complementary approaches work.

### 1.1 Dynamic analysis: MITM the device

This is the most direct path — intercept the TLS connection `locationd` opens when it asks
Apple for the positions of nearby access points.

1. **Run a proxy on your computer** — mitmproxy, Charles, or Burp Suite.
2. **Install the proxy's CA certificate on the device:**
   - iOS: visit the proxy's install URL (e.g. `http://mitm.it`), install the profile, then
     enable full trust in *Settings → General → About → Certificate Trust Settings*.
   - macOS: install the CA into the System keychain and mark it trusted.
3. **Route the device's traffic through the proxy** — same Wi-Fi with manual proxy config,
   or a tethered connection.
4. **Trigger a Wi-Fi positioning request.** `locationd` fires when Location Services is
   enabled and the device needs a network-based fix, for example:
   - toggle Location Services off and on,
   - open Maps and let it settle,
   - disable/re-enable Wi-Fi so the scan list changes.
5. **Filter the capture** for the host. The interesting request is a `POST` whose path is
   `/clls/wloc` and whose body is binary (it will not render as text in the proxy).

Key observations from doing this:

- `locationd` uses the system TLS stack (CFNetwork) and **does not pin certificates** —
  once the proxy CA is trusted, the request/response are fully readable.
- The same message pattern also shows up against `iphone-services.apple.com/clls/wloc`
  (an alternate host serving the same service) and against a China mirror
  (`gs-loc-cn.apple.com`).
- Longer monitoring of a device with *Improve Maps* / *iPhone Analytics* enabled reveals
  related endpoints of the same family: a cell+WIFI submission endpoint
  (`gsp10-ssl.apple.com/hcy/pbcwloc`, labelled `CLPCellWifiCollectionRequest`) and a tile
  endpoint that returns whole regions of BSSIDs (`gspe85-ssl.ls.apple.com/wifi_request_tile`).
  Only `/clls/wloc` is needed for lookups.

### 1.2 Static analysis: find the schema in the binaries

Traffic capture gives you bytes; disassembly gives you names.

- **macOS ships `CoreLocationProtobuf.framework`.** Disassembling it exposes the protobuf
  message and field names (`CLP...` prefixed types), which turns anonymous field numbers
  into readable ones (`latitude`, `accuracy`, `num_wifi_results`, …).
- **`strings locationd`** (iOS/macOS) confirms the client identity used in the
  `User-Agent` header and the `com.apple.locationd` bundle identifier baked into the
  envelope.

Between the two — bytes from the wire, names from the binary — the whole protocol becomes
recoverable without Apple ever publishing a `.proto` file.

---

## 2. Why this is not a REST/JSON API

A typical commercial geolocation API accepts a JSON body:

```json
{ "wifiAccessPoints": [ { "macAddress": "24:0b:2b:11:5d:d9" } ] }
```

One POST, `Content-Type: application/json`, response is JSON. Trivial to call from anything.

Apple's endpoint looks superficially similar — one POST — but every layer under the header
is binary:

| | Typical JSON API | Apple WLOC |
| --- | --- | --- |
| Request body | JSON text | Custom 50-byte envelope + protobuf |
| `Content-Type` | `application/json` | `application/x-www-form-urlencoded` **(wrong/misleading)** |
| Schema | Published OpenAPI/JSON schema | None — recovered from captures + disassembly |
| Encoding | UTF-8, self-describing | Protobuf varints: compact, not human-readable |
| Response | JSON with field names | Binary stream, 10-byte header, then protobuf |
| Numbers | JSON floats | Fixed-point integers (`×1e8`), sentinel values |

Two consequences that decide the whole implementation:

1. **The header lies.** The real captured header dump (see §4.1) says
   `Content-Type: application/x-www-form-urlencoded`, yet the body is neither form data nor
   URL-encoded — it is binary. Any client that tries to parse the body as a form will fail.
   The server apparently does not care what the header claims.
2. **You need a schema, or you need to write one.** Standard practice is to reconstruct a
   `.proto` file from captured messages (aided by the disassembled field names) and generate
   code with `protoc`. This library takes the other road: a **hand-rolled ~100-line encoder/
   decoder** for exactly the subset of protobuf the protocol uses (see §9). That keeps the
   dependency count at zero and the whole thing inside one file.

This is why generic "how do I geolocate Wi-Fi" answers skip this endpoint: a client is maybe
500 lines of binary protocol work before any geolocation logic happens at all.

---

## 3. Anatomy of a request

```
POST /clls/wloc HTTP/1.1
Host: gs-loc.apple.com
Content-Type: application/x-www-form-urlencoded
User-Agent: locationd/1753.17 CFNetwork/711.1.12 Darwin/14.0.0
Accept-Encoding: gzip, deflate

┌──────────────────────────────┬─────────────────────────────┐
│ fixed 50-byte envelope       │ 1-byte payload length       │
│ (see §4.2)                   │ + protobuf payload (≤255B)  │
└──────────────────────────────┴─────────────────────────────┘
```

### 3.1 The payload

The payload is a protobuf message. Conceptually:

```proto
message WifiRequest {
  repeated Device devices = 2;   // one per requested BSSID
  optional int64  unknown  = 3;  // always observed as 0
  optional int64  num_wifi_results = 4;  // 0 = also return neighbours, 1 = only requested
}

message Device {
  required string bssid = 1;     // e.g. "24:0b:2b:11:5d:d9"
}
```

Note the field numbers: there is no field `1` at the top level — the outer message starts
at `2`. That is a fingerprint of a schema that evolved over time, and a good sign you are
looking at the real format rather than a cleaned-up reconstruction.

`num_wifi_results` (field 4) is the single most useful knob:

- `0` — Apple returns the requested BSSIDs **plus up to ~100 surrounding access points** it
  believes are nearby. Bigger picture, wider spread.
- `1` — Apple returns **only the BSSIDs you asked for**. Tight, fast, fewer bytes.

### 3.2 Batching

The payload must fit in **255 bytes** (its length is written as a single byte in the
envelope). Cost per BSSID entry = `4 + len(bssid)` (2 tag/length bytes for the outer
`Device` message, 2 for the inner BSSID string; a 17-byte MAC string such as
`"24:0b:2b:11:5d:d9"` therefore costs 21 bytes including overhead). Batches are packed
greedily: append BSSIDs until the next one would overflow, close the batch, start a new
request. Keep-alive on the TLS connection makes multi-batch queries cheap.

---

## 4. The wire format, byte by byte

### 4.1 Captured HTTP layer

```
POST /clls/wloc HTTP/1.1
Host: gs-loc.apple.com
Content-Type: application/x-www-form-urlencoded
Accept: */*
Accept-Charset: utf-8
Accept-Encoding: gzip, deflate
Accept-Language: en-us
User-Agent: locationd/1753.17 CFNetwork/711.1.12 Darwin/14.0.0
```

The `User-Agent` is the tell: `locationd` + a CFNetwork build string + a Darwin version.
Reproducing it makes the request indistinguishable from a real device as far as the
server appears to care. Responses may arrive gzip-compressed despite the form-urlencoded
content type — decompress on `Content-Encoding: gzip` (and defensively if the body starts
with the gzip magic `1f 8b`).

### 4.2 The 50-byte envelope

Every request body starts with this fixed header. Byte-annotated:

```
Offset  Len  Bytes                                    Meaning
------  ---  ---------------------------------------  ----------------------------------
0x00    2    00 01                                    fixed prefix (semantics unknown;
                                                      stable across all captures)
0x02    2    00 05                                    length of following string = 5
0x04    5    65 6e 5f 55 53                            "en_US"
0x09    2    00 13                                    length = 19
0x0B   19    63 6f 6d 2e 61 70 70 6c 65 2e 6c 6f     "com.apple.locationd"
            63 61 74 69 6f 6e 64
0x1E    2    00 0a                                    length = 10
0x20   10    38 2e 31 2e 31 32 42 34 31 31            "8.1.12B411" (build/version)
0x2A    7    00 00 00 01 00 00 00                     fixed trailer (semantics unknown)
0x31    1    XX                                       payload length (0–255)
0x32    n    (payload)                                protobuf message, n = byte above
```

Fixed prefix total: **50 bytes including the length byte.** Of these, the string fields
(locale, bundle id, version) are self-describing; the three fixed markers
(`00 01`, the `00 00 00 01 00 00 00` trailer) never changed across any capture and can be
treated as constants.

Full hex of the envelope for a 25-byte payload (length byte `19`):

```
00010005 656e5f5553 0013 636f6d2e6170706c652e6c6f636174696f6e64
000a 382e312e313242343131 00000001000000 19
```

### 4.3 Protobuf primer (the parts this protocol uses)

Protocol Buffers encodes each value as a **tag + payload**. The tag is a varint of
`(field_number << 3) | wire_type`:

| wire_type | Meaning | Used here |
| --- | --- | --- |
| 0 | varint (int32/int64/uint64/bool) | lat, lng, accuracy, flags |
| 2 | length-delimited (string/bytes/nested) | BSSID strings, nested messages |
| 1, 5 | fixed64 / fixed32 | not used in this protocol |

**Varint** = 7 bits per byte, low group first, high bit `0x80` = "more bytes follow":

```
25      → 19                (single byte, 0x19)
1601742172 → dc ca e2 fb 05  (5 bytes)
-180    → cc fe ff ff ff ff ff ff ff 01   (int64 two's complement, 10 bytes)
```

Because wire type 2 values carry their own length byte, nested messages compose naturally:

```
field2 (Device)        tag = (2<<3)|2 = 0x12, then length, then body
  field1 (bssid)       tag = (1<<3)|2 = 0x0a, then length, then ASCII
field3 (varint)        tag = (3<<3)|0 = 0x18, then value
field4 (varint)        tag = (4<<3)|0 = 0x20, then value
```

Negative int64s are encoded as unsigned 64-bit two's complement — i.e. a 10-byte varint
(`value + 2^64`). This matters for the `-180` sentinel in responses (§5.2).

### 4.4 Request example, full hex

One request, one BSSID `aa:bb:cc:dd:ee:ff`, neighbours on (`field4 = 0`):

```
payload (25 bytes):
  12 13                     field2, LEN, 19 bytes
    0a 11                   field1, LEN, 17 bytes
      61613a62623a63633a64643a65653a6666   "aa:bb:cc:dd:ee:ff"
  18 00                     field3 = 0
  20 00                     field4 = 0  (also return neighbours)

full body (75 bytes):
  00010005656e5f55530013636f6d2e6170706c652e6c6f636174696f6e64000a
  382e312e3132423431310000000100000019
  12130a1161613a62623a63633a64643a65653a666618002000
```

(These are the exact golden vectors the test suite asserts against — see
[PORTING.md](PORTING.md).)

---

## 5. The response

### 5.1 Structure

```
┌──────────────┬─────────────────────────────────────────────┐
│ 10 bytes     │ protobuf: repeated wifi entries (field 2)   │
│ fixed header │                                             │
└──────────────┴─────────────────────────────────────────────┘
```

- **First 10 bytes are a fixed header** (a response counterpart of the request envelope).
  Their contents are not needed for parsing — skip them and decode the remainder.
- The rest is a protobuf message whose field 2 (wire type 2) repeats once per access
  point:

```proto
message WifiResponse {
  repeated Wifi wifi = 2;
}

message Wifi {
  required string  bssid      = 1;
  optional Location location  = 2;

  message Location {
    optional int64 latitude          = 1;  // fixed-point, ×1e8
    optional int64 longitude         = 2;  // fixed-point, ×1e8
    optional int64 accuracy         = 3;  // metres
    // fields 4+ (altitude, vertical accuracy, …) exist but are not needed for 2D fixes
  }
}
```

### 5.2 Decoding rules

1. **Scale:** `latitude = raw / 1e8`. `1601742172 → 16.01742172`.
2. **Sentinel:** an unknown BSSID comes back with `latitude = longitude = -180`
   (encoded as a 10-byte two's-complement varint, unsigned value `2^64 − 180`) and
   typically `accuracy = -1`. Drop these — the BSSID simply is not in Apple's database.
   Sanity-check `accuracy` to `[0, 10000]`; anything else is treated as absent.
3. **Echo quirk:** the response string is echoed verbatim, and echoes may be
   *non-canonical* — single-digit octets appear (`24:b:2b:11:5d:d9`). The parser must
   zero-pad octets, not assume `^[0-9a-f]{2}(:...){5}$`.
4. **Dedupe:** later entries for the same (normalized) BSSID win; first response wins in
   practice — the list is deduplicated on insert.
5. **Compression:** if the body starts with `1f 8b`, gunzip first (some paths compress
   even when not announced).

### 5.3 Response example, full hex

Synthetic response for `aa:bb:cc:dd:ee:ff` at `(16.01742172, 108.20785522)`, `acc = 25`:

```
00000000 0000000000                          10-byte header (skip)
12 23                                          field2, LEN, 35 bytes
  0a 11                                        field1 (bssid), LEN, 17
    61613a62623a63633a64643a65653a6666          "aa:bb:cc:dd:ee:ff"
  12 0e                                        field2 (location), LEN, 14
    08 dc ca e2 fb 05                          latitude  = 1601742172
    10 f2 aa e0 a7 28                          longitude = 10820785522
    18 19                                      accuracy  = 25
```

---

## 6. Experimental quirks (measured, not guessed)

Requests were sent with deliberately malformed inputs; the table is what came back.

| Input form | Sent as | Result |
| --- | --- | --- |
| `24:0b:2b:11:5d:d9` (canonical, lowercase) | verbatim | normal response with fixes |
| `240b2b115dd9` (no separators) | verbatim | **empty 10-byte response** — server expects a text MAC |
| uppercase / single-digit octets | normalized client-side | response may echo non-canonical form (§5.2) |
| unknown BSSID | valid MAC | sentinel `-180` entry, `accuracy = -1` |
| 40+ BSSIDs | batched ≤ 255 B | multiple requests, all answered normally |
| repeated rapid queries | keep-alive | see §7 |

Practical rules the library enforces as a result:

- **Normalize before sending:** lowercase, colon-separated, zero-padded octets
  (`wifilocate.norm()` accepts `str`, hex strings, 6 raw bytes, `-`/`.` separators).
- **Normalize again on receive**, because the echo is not trustworthy.
- **Never trust the `Content-Type`** — parse bytes, not form data.

---

## 7. Throttle behavior

The server rewards restraint. Observed behavior during bulk testing:

- A response that returns **many fixes at once (≥ 17)** coincided with the server being in a
  permissive "dump" mode; continuing to request surrounding neighbours in that state risks
  degraded answers and `429 Too Many Requests`.
- The client therefore treats "returned ≥ 17 fixes" as a **throttle signal** and switches
  to `num_wifi_results = 1` (requested BSSIDs only) for the next **10 seconds** — it stops
  *asking for extra data*, it does not sleep.
- A naive interpretation (sleep 10 s on the signal) measured **10.9 s** for a
  requested-only query and **20.5 s** for a neighbours query. The correct interpretation
  (suppress neighbours instead of sleeping) measured **2.3 s** for both.

HTTP-level handling as a second line of defense:

- `429` → honor `Retry-After` if present, otherwise exponential backoff (`0.6s, 1.2s, 2.4s`),
  up to 3 attempts.
- `5xx` → exponential backoff, 3 attempts.
- connection errors → reconnect (fresh TLS) and retry.
- `0.5 s` minimum spacing between requests on one connection.

---

## 8. Mirrors and fallback

| Host | Role |
| --- | --- |
| `gs-loc.apple.com` | primary endpoint used by this library |
| `iphone-services.apple.com` | alternate host, same `/clls/wloc` path |
| `gs-loc-cn.apple.com` | China mirror |
| `gs-loc.apple.grapheneos.org` | GrapheneOS proxy that forwards WLOC traffic |

The library uses the GrapheneOS proxy as an **automatic fallback**: if the primary endpoint
errors out (network-level failure, blocking), the same query is retried there, and the
resulting `Location.source` records which host answered. Custom endpoints are exempt from
fallback — if you point the client somewhere yourself, failures propagate to you.

---

## 9. Implementing without a `.proto` file

Two valid strategies:

1. **Reconstruct the schema** (`.proto` → `protoc` → generated classes). Best when you want
   field names, optional-field semantics, and future fields for free. Cost: a code-generation
   step and a protobuf runtime dependency.
2. **Hand-roll the codec** (what this library does). The protocol uses only varints,
   length-delimited strings, and one nesting level — ~40 lines to encode, ~60 lines to
   decode:

```python
def varint(v: int) -> bytes:            # 7-bit groups, continuation bit 0x80
    out = bytearray()
    while True:
        b, v = v & 0x7F, v >> 7
        out.append(b | (0x80 if v else 0))
        if not v:
            return bytes(out)

def fstr(num: int, s: str) -> bytes:    # length-delimited field
    raw = s.encode()
    return varint((num << 3) | 2) + varint(len(raw)) + raw

def fvar(num: int, v: int) -> bytes:    # varint field (negative → 10-byte two's complement)
    return varint(num << 3) + varint((v + (1 << 64)) if v < 0 else v)
```

The decoder mirrors it: read tag → switch on wire type → recurse into wire-type-2 buffers.
Anything unrecognized ends parsing gracefully (unknown wire types 3/4 are treated as
end-of-stream), so a future field added by Apple does not crash old clients.

This trade-off — no schema, no codegen, zero dependencies — is the right call for a
single-file library and for embedded ports where `protoc` output is unwanted. It is also
exactly why this endpoint gets skipped by generic API tutorials: someone has to do the byte
work first. This document, plus the golden vectors in [PORTING.md](PORTING.md), is that work
written down.
