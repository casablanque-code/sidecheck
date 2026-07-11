# Realistic fixtures

Unlike `test-fixture/` (Python, artificially amplified — 400μs of added
delay per matched byte, purely to validate the measurement pipeline
end-to-end), these fixtures use **real, unmodified** comparisons exactly as
they're commonly written — no delay added. The leak here, if measurable at
all, is whatever a naive `==`/`===` actually costs on real hardware: likely
nanoseconds to low microseconds, not milliseconds.

This is the honest test of whether `sidecheck` is useful in practice, not
just correct in principle.

## go-nethttp

Go standard library only, no external dependencies (`go.mod` isn't even
needed for `go run`).

```sh
cd go-nethttp && go run main.go
# serves on http://127.0.0.1:8001
#   /vulnerable — real == comparison
#   /safe       — crypto/subtle.ConstantTimeCompare
```

## node-http

Node built-in `http`/`crypto` modules only, zero npm dependencies.

```sh
cd node-http && node server.js
# serves on http://127.0.0.1:8002
#   /vulnerable — real === comparison
#   /safe       — crypto.timingSafeEqual
```

## Expectations

A quick informal probe (not the real box test — just alternating requests
and comparing raw p10) against both, over loopback, found a difference on
the order of ~10μs — smaller than the request-to-request noise from the
HTTP stack itself, and not even reliably in the expected direction. That's
not a failure of the fixtures or of `sidecheck`; it's a preview that a
realistic same-machine leak may sit right at or below the noise floor of
an HTTP-level measurement, which is exactly the kind of honest limit
`sidecheck doctor`/`check` should surface on their own, with proper
statistics, rather than a hand-wavy "yes/no."

Secret for both: `correct-secret-key-123456`

```sh
sidecheck doctor http://127.0.0.1:8001/vulnerable
sidecheck check http://127.0.0.1:8001/vulnerable --header X-API-Key --secret correct-secret-key-123456
sidecheck check http://127.0.0.1:8001/safe       --header X-API-Key --secret correct-secret-key-123456

sidecheck doctor http://127.0.0.1:8002/vulnerable
sidecheck check http://127.0.0.1:8002/vulnerable --header X-API-Key --secret correct-secret-key-123456
sidecheck check http://127.0.0.1:8002/safe       --header X-API-Key --secret correct-secret-key-123456
```
