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

## Finding the crossover point

25 bytes turned out too short to detect over real HTTP — CI narrowed to
sub-microsecond with 200,000 samples/class and still found nothing
significant. That's an honest result (see main README's Limitations), not
a failure: a real `==` leak on a 25-byte string is plausibly tens of
nanoseconds, swamped by everything above raw CPU cycles once you're
measuring through a socket.

Both fixtures support `SECRET_LEN` to scale the secret up — a longer
secret means more comparisons before an early exit, so the leak should
grow roughly linearly with length. Use this to find where it becomes
detectable over HTTP:

```sh
SECRET_LEN=500  go run main.go     # or: SECRET_LEN=500 node server.js
```

The secret is built deterministically by repeating the base pattern, so
`--value-b` needs the actual printed secret (it's logged at startup) rather
than the original 25-byte one. Try a few points (100 / 500 / 2000 / 10000
bytes) with `doctor` first to check the channel is still `GOOD`, then
`check`, and see where the CI stops including zero.

## Running the default (25-byte) fixtures

Secret for both: `correct-secret-key-123456`

```sh
sidecheck doctor http://127.0.0.1:8001/vulnerable
sidecheck check http://127.0.0.1:8001/vulnerable --header X-API-Key --secret correct-secret-key-123456
sidecheck check http://127.0.0.1:8001/safe       --header X-API-Key --secret correct-secret-key-123456

sidecheck doctor http://127.0.0.1:8002/vulnerable
sidecheck check http://127.0.0.1:8002/vulnerable --header X-API-Key --secret correct-secret-key-123456
sidecheck check http://127.0.0.1:8002/safe       --header X-API-Key --secret correct-secret-key-123456
```
