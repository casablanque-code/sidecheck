# sidecheck

How do you know your password comparison is actually constant-time?

Measure it.

`sidecheck` is a CLI tool that audits your own HTTP endpoints for remote
timing side-channels — the class of bug where comparing a secret with `==`
lets an attacker recover it character-by-character by measuring response
time instead of brute-forcing the whole thing.

It is built as a measuring instrument, not an exploit: it tells you whether
a measurable timing channel exists and how confident it is, not "here is
your password."

## Why this matters

AI-assisted ("vibe") coding has made this class of bug far more common —
LLMs reliably write auth comparisons that work and pass tests, but aren't
constant-time. If your login endpoint was written with Claude/Copilot/Cursor
and never had a security review, there's a good chance nobody has checked
this.

## Methodology

Naive mean/median timing analysis on network measurements is unreliable —
network jitter is orders of magnitude larger than the CPU-level signal
you're trying to detect. `sidecheck` uses the methodology from Crosby,
Wallach & Riedi, *"Opportunities and Limits of Remote Timing Attacks"*
(ACM TISSEC, 2009):

- network noise can only **add** delay, never remove it, so low percentiles
  (e.g. p10) of a sample carry far less noise than the mean or even the raw
  minimum
- a **box test** compares the low percentile of two classes of requests
  (e.g. "correct prefix" vs "wrong prefix")
- confidence intervals are computed via bootstrap resampling — no
  assumption of normally-distributed network latency
- request order is randomized in interleaved blocks (never "all A, then all
  B") so time-of-day drift or server warm-up doesn't bias the result
- before the full run, a pilot batch estimates network jitter and reports
  how many samples are actually needed to detect a leak of a given size —
  if the network is too noisy for the target signal, it says so honestly
  instead of guessing

## Usage

Simple mode — give it your real secret, it generates a matching-length wrong
value automatically:

```sh
sidecheck check https://myapp.local/login \
  --header X-API-Key \
  --secret "my-real-api-key-do-not-share"
```

Sample size is picked automatically from a quick pilot run — you don't need
to guess `--samples` up front. Works against any of three injection points:

```sh
# HTTP header (API keys, tokens)
sidecheck check https://myapp.local/api --header X-API-Key --secret "..."

# query parameter (legacy token-in-URL endpoints)
sidecheck check https://myapp.local/api --query token --secret "..."

# JSON POST body field (typical web login forms)
sidecheck check https://myapp.local/login --json-field password --secret "..."
```

Advanced mode — full control over both compared values (e.g. to test a
specific guessed prefix instead of the full secret):

```sh
sidecheck check https://myapp.local/login \
  --header X-API-Key \
  --value-a "0000000000000000000000000" \
  --value-b "correct-se0000000000000000" \
  --samples 5000
```

```
────────────────────────────────────────────────
sidecheck timing report
────────────────────────────────────────────────

target          https://myapp.local/login
field            header X-API-Key
samples/class    12480
network jitter   1.80 ms

⚠ timing leak detected
  estimated leak   31.4 μs
  confidence       95.0%

  this endpoint responds measurably differently depending on
  input correctness. an attacker can exploit this to recover
  secrets character-by-character instead of brute-forcing them.

  fix: use a constant-time comparison instead of == on secret
  bytes (e.g. the `subtle` crate in Rust, `crypto/subtle` in Go,
  `hmac.compare_digest` in Python).
```

## Self-verification

`test-fixture/test_fixture.py` is a small reference server with a
deliberately vulnerable `/vulnerable` endpoint and a safe `/safe` endpoint
using `hmac.compare_digest`. Use it to confirm `sidecheck` correctly flags
the vulnerable one and stays silent on the safe one before trusting it on a
real target:

```sh
python3 test-fixture/test_fixture.py &
sidecheck check http://127.0.0.1:8000/vulnerable --header X-API-Key --secret "correct-secret-key-123456"
sidecheck check http://127.0.0.1:8000/safe        --header X-API-Key --secret "correct-secret-key-123456"
```

## Status

`v0.1` — detection only, single HTTP header field. Planned next: SSH/TLS key
entropy auditing (shared-prime-factor detection via batch-GCD across your
own fleet), then a TCP raw-socket adapter.

## Build

Requires a recent stable Rust toolchain (edition 2021, current crates need
a fairly modern `rustc` — install via [rustup](https://rustup.rs), not your
distro's package manager).

```sh
cargo build --release
./target/release/sidecheck check --help
```

## License

MIT
