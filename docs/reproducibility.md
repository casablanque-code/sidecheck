# Reproducibility

## Seeds

Every run picks (or accepts via `--seed`) a seed that determines the
request interleaving order and the generated wrong value. It's printed in
both the terminal report and the JSON output — pass it back with `--seed`
to reproduce the exact same request sequence, e.g. when debugging an odd
result.

With `--repeat`, `--seed` reproduces the *whole sequence* of runs, not a
single run in isolation — each repeat continues drawing from the same RNG
stream rather than restarting it.

Note that the seed fixes the request order and the wrong-value generation
only — it does not fix the actual measured timings, which come from a
real network on every run. Two runs with the same seed against a target
with real, unpredictable network noise will still produce different raw
latencies; what stays identical is which request goes out in which slot.

## Checking whether one run's estimate can be trusted

A single run's `estimated leak` is one point estimate; it doesn't tell
you whether that number would look similar if you ran it again. `--repeat
N` runs the full pilot+measurement cycle N times and summarizes how much
the estimate and the significance verdict actually move around — see
[statistics.md](./statistics.md#stability-across---repeat-runs) for how
that summary is computed and why significance agreement is weighted over
raw variance.

```sh
sidecheck check https://myapp.local/login --header X-API-Key --secret-env API_KEY --repeat 5
```

```
────────────────────────────────────────────────
stability summary across 5 runs
────────────────────────────────────────────────

significant in 5/5 runs
estimated leak   mean 12.23 ms · range [12.20 ms, 12.25 ms] · std dev 21.8 μs

✓ consistently significant with a stable magnitude across runs.
```

With `--output-csv`/`--report`, each repeat gets its own file
(`report-run1.json`, `report-run2.json`, ...) rather than overwriting the
same one N times.

## Reports for CI / automation

```sh
sidecheck check https://myapp.local/login --header X-API-Key --secret-env API_KEY \
  --report report.json --output-csv raw.csv
```

`report.json` carries the sidecheck version, seed, and timestamp alongside
the verdict — a report from an older version shouldn't be trusted the
same way as one from a future version with improved statistics.
`raw.csv` has the individual per-request measurements (`class,
elapsed_seconds`) for anyone who wants to independently re-run the
statistics rather than trust sidecheck's own numbers.

## Comparing against a baseline

A leak being present isn't automatically something a given change should
be blamed for — it might have already been there. `sidecheck compare`
checks whether a *new* leak was introduced relative to a baseline report,
rather than flagging any leak at all:

```sh
sidecheck compare baseline.json current.json
```

Exits `1` (and prints why) only when the baseline was clean and the
current run is significant — a pre-existing leak present in both reports
is still reported, but doesn't fail the comparison, since re-flagging a
problem that predates the change under test isn't useful signal for a
per-change CI gate. An improvement (baseline leaked, current doesn't)
exits `0` too, with a note to verify it's a real fix rather than a
noisier run — see [limitations.md](./limitations.md) on what a clean
result does and doesn't mean.

Comparing reports for different targets or injection points still runs,
but prints a warning first — useful for spot-checking, less useful as an
unattended CI gate, so make sure both sides of the comparison are testing
the same endpoint and field before wiring this into automation.

This is the building block for a CI gate (baseline from the base branch,
current from the PR) — see [ROADMAP.md](../ROADMAP.md) for where that's
headed; `compare` itself doesn't yet know how to fetch or store a
baseline across CI runs, only how to compare two report files you already
have.

## Self-verification

`test-fixture/test_fixture.py` is a small reference server with a
deliberately vulnerable `/vulnerable` endpoint and a safe `/safe`
endpoint using `hmac.compare_digest`. Use it to confirm `sidecheck`
correctly flags the vulnerable one and stays silent on the safe one
before trusting it on a real target:

```sh
python3 test-fixture/test_fixture.py &
sidecheck check http://127.0.0.1:8000/vulnerable --header X-API-Key --secret "correct-secret-key-123456"
sidecheck check http://127.0.0.1:8000/safe        --header X-API-Key --secret "correct-secret-key-123456"
```

`realistic-fixtures/` has non-amplified Go, Node, and Python (JSON login)
reference servers for a more honest end-to-end check — see
`realistic-fixtures/README.md` and
[limitations.md](./limitations.md#real-world-detectability-at-short-secret-lengths).
