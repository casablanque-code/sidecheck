# Limitations and status

## sidecheck cannot prove the absence of a timing leak

A clean result means no statistically significant difference was found
*under the tested conditions* — this sample size, this network path, this
percentile. It does not mean the endpoint is safe. A smaller leak, a
noisier network, or a different code path could still hide a real issue.

Treat a positive result as strong evidence of a bug. Treat a negative
result as "nothing found here," not a certificate of safety.

## What "confidence" does and doesn't mean

`bootstrap confidence` in the report is the confidence level of the
bootstrap-resampled interval around the measured difference. It answers
"how sure are we this specific difference isn't just noise" — not "what's
the probability this server is vulnerable," and it is not a p-value in
the classical hypothesis-testing sense. See
[statistics.md](./statistics.md) for the full derivation.

## sidecheck can't tell whether your injection actually reached the code path under test

This is a methodology blind spot worth knowing about explicitly: if both
the "correct" and "wrong" classes get rejected for the *same* reason
before the code path you're actually trying to test — for example, a
`/login` endpoint that checks `username` before it ever looks at
`password`, and both classes send an unrecognized username — the response
times will be identical regardless of whether the password comparison
itself is vulnerable. `sidecheck` will honestly (and misleadingly) report
"no significant difference," because from its perspective there genuinely
wasn't one in what it measured. It has no way to know the comparison you
care about was never reached.

This is exactly why `--json-body` (see the main README) exists — to let
you supply whatever other fields a realistic endpoint needs to get past
an early exit and into the comparison you're actually auditing. When
setting up a target, check response codes/bodies for both classes
manually first (e.g. with `curl`) to confirm they're both reaching the
comparison you intend to test, not just failing the same early gate.

## Real-world detectability at short secret lengths

The non-amplified reference fixtures (`realistic-fixtures/`, Go and Node,
using real `==`/`===` with no artificial delay) show that a genuine leak
on a short secret (25 bytes) is often *not* reliably detectable over real
HTTP — the noise floor of a real request, even over loopback, can exceed
a nanosecond-scale CPU-level leak entirely. That's an honest limit of the
method, not a bug. See `realistic-fixtures/README.md` for how to find the
crossover secret length where a real leak becomes HTTP-detectable on your
own hardware.

## Status

Working and validated end-to-end: detection (`check`), pre-flight
diagnostics (`doctor`), the amplified Python fixture for pipeline
validation, and two non-amplified reference fixtures (Go and Node)
confirming the detectability limits above.

Not yet done: reference targets for FastAPI/Express/Actix/Axum/Spring
(only Go/Node so far), a longer-secret sweep to find the HTTP-detectable
crossover length as a documented data point rather than something you
have to discover yourself, and CI coverage of the realistic (non-amplified)
Go/Node fixtures specifically — CI does run `check`/`doctor` end-to-end
against the amplified Python fixture (header and `--json-body` injection,
positive and negative cases, argument-validation regressions) plus
fmt/clippy/unit tests, but not yet the Go/Node fixtures, since those need
toolchains CI doesn't currently install.

See [ROADMAP.md](../ROADMAP.md) for planned features, including a
GitHub Action for CI timing-regression gates.
