# Positioning Algorithm

How `wifilocate` turns a bag of per-BSSID fixes into one position with an accuracy figure
and a confidence score.

```
BSSIDs ──▶ filter ──▶ batch+query ──▶ parse ──▶ reject outliers ──▶ weighted centroid
                (RSSI)     (WLOC)      (×1e8)      (median)           w = 1/(1+acc²)
                                                                        │
                                              accuracy ◀── spread ──────┤
                                              confidence ◀── n, spread ─┘
```

All steps after `query` are pure functions — no IO, deterministic, unit-testable, and
portable to any language (see [PORTING.md](PORTING.md)).

## 1. Input filtering (`_filter`)

Garbage in, garbage out: distant or sleeping APs pollute the centroid.

- Default floor: **`min_rssi = -90` dBm**. APs below it are dropped.
- APs with **unknown RSSI are kept** — you rarely lose by including them; Apple may still
  know them.
- **Floor escape hatch:** if fewer than **3** APs survive the filter, the filter is skipped
  entirely and all APs are sent. A tiny scan list must not be filtered down to nothing.

Windows `netsh` reports signal as a percentage, not dBm; `scan()` converts with
`rssi ≈ -100 + pct × 0.6` clamped to `[-100, -50]` (0% → -100, 100% → -40→clamped -50).
Embedded platforms (ESP32) report true dBm and bypass this.

## 2. Query (`AppleClient.query`)

- BSSIDs are packed greedily into batches whose encoded payload stays **≤ 255 bytes**
  (cost per BSSID = `4 + len(bssid)`; see RE doc §3.2).
- One keep-alive TLS connection serves all batches, **0.5 s** minimum spacing.
- `neighbours=True` (default) sends `num_wifi_results = 0`: Apple returns the requested
  BSSIDs **plus ~100 surrounding APs**. After a response with **≥ 17 fixes** the client
  considers itself throttled and downgrades to `num_wifi_results = 1` for 10 s (request
  suppression, not sleep — see RE doc §7).
- Retries: 3 attempts, exponential backoff, `Retry-After` honored on HTTP 429.

## 3. Outlier rejection (`reject_outliers`)

Apple occasionally returns a fix kilometers away (stale survey data, APs moved). One bad
point drags a plain mean badly, so:

1. If **< 3 fixes** — nothing to reject, pass through.
2. Compute the **median latitude and median longitude** separately — the center point.
   (A mean would be dragged by the very outlier we want to remove; the median is not.)
3. Threshold: **`max(100 m, 3 × median_accuracy)`** — at least 100 m, more if Apple itself
   reports poor accuracy.
4. Drop any fix farther from the center than the threshold.
5. If that would drop *everything* (pathological case), return the original list — never
   return empty.

Measured effect on the synthetic test case (two APs 15 m apart + one 4.7 km away): the far
fix is removed, remaining two produce a clean centroid.

## 4. Centroid (`weighted_centroid`)

Each surviving fix votes for the final position with weight

```
w = 1 / (1 + accuracy²)
```

(`accuracy` defaults to 50 m when missing.) A 10 m fix weighs 101× more than a 100 m fix,
but no single fix dominates — the function is bounded and smooth, so the result sits near
the cluster of good fixes without oscillating. Then:

```
lat = Σ(fix.lat × w) / Σw
lng = Σ(fix.lng × w) / Σw
```

This is deliberately simple. Multilateration (EM/trilateration over RSSI) was considered
and rejected: BSSIDs returned by Apple are *positions of APs*, not ranges from you, and they
cluster on the building/neighborhood scale — a weighted centroid over accurate points
already lands within a few metres of any statistical estimator, with none of the convergence
failure modes.

With `refine=False` the first fix is returned verbatim (debugging / single-AP mode).

## 5. Accuracy

```
accuracy = max( max(fix.accuracy), spread / 2 )
```

- `max(fix.accuracy)` — trust Apple's own worst-case radius.
- `spread / 2` — half the maximum pairwise distance between fixes
  (`spread` = largest haversine distance in the set). If Apple's per-AP radii are tiny but
  the fixes themselves are scattered, spread catches it.

Reported as `±N m`. For an honest figure: fixes that agree tightly → spread dominates
nothing, accuracy ≈ Apple's radii; fixes that disagree → spread dominates and the number
grows.

## 6. Confidence

```
score  = 0.3                                # base: we have *something*
       + min(0.4, 0.1 × (n_fixes − 1))      # more corroborating fixes, up to +0.4 (5 fixes)
       + min(0.3, 0.3 × (1 − min(spread,100) / 100))   # tight cluster bonus, up to +0.3
confidence = clamp(score, 0, 1)
```

Interpretation: **≥ 0.7** — good (several fixes, tight cluster); **0.4–0.7** — usable;
**< 0.4** — treat skeptically (1–2 fixes or heavy scatter). Reported accuracy ± meters is
the spatial radius; confidence is how much the evidence agrees with itself — they answer
different questions, check both.

## 7. Trade-off: neighbours on vs off

The single biggest quality knob is `neighbours` (`num_wifi_results`).

| | `neighbours=False` | `neighbours=True` (default) |
| --- | --- | --- |
| Apple returns | only requested BSSIDs | requested + ~100 surrounding |
| Typical fix count | ~25 (your scan) | ~100 |
| Spread / reported acc | tight, ±38 m | wide, ±94 m |
| Error vs OS ground truth (example) | ~10 m | ~40 m |
| Wall time (example) | 2.3 s | 2.3 s |
| Best for | "where am I now", embedded | neighborhood context, research |

Why the dump is wider: surrounding APs are, by definition, *around* you — their centroid
includes the neighbours' premises too, and stale entries among them add scatter. The extra
fixes are not useless (they corroborate the neighborhood), but for a single position the
requested-only mode is measurably tighter.

**Recommendation:** keep `neighbours=True` for exploratory use (richer `Location.fixes`
list to inspect), switch to `neighbours=False` when the coordinate itself matters.

## 8. Measured results (example session)

Redacted coordinates; ground truth from the OS location API (reported `±135 m`).

| Mode | Error vs truth | Reported acc | Confidence | Fixes | Time |
| --- | --- | --- | --- | --- | --- |
| `neighbours=False` | ~10 m | ±38 m | 0.78 | ~24 | 2.3 s |
| `neighbours=True` | ~40 m | ±94 m | 0.70 | ~98 | 2.3 s |

Accuracy of an individual Apple fix in this session: `±25–40 m` typical. The library's
reported figure is deliberately conservative (worst radius or spread/2, whichever is
larger) and never claims better than the evidence supports.
