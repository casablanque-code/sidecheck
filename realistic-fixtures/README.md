# Realistic fixtures

Unlike `test-fixture/` (Python, artificially amplified — 400μs of added
delay per matched byte, purely to validate the measurement pipeline
end-to-end), these fixtures use **real, unmodified** comparisons exactly as
they're commonly written — no delay added. The leak here, if measurable at
all, is whatever a naive `==`/`===` actually costs on real hardware: likely
nanoseconds to low microseconds, not milliseconds.

This is the honest test of whether `sidecheck` is useful in practice, not
just correct in principle.

## Testing from a real vantage point (not loopback)

These fixtures bind to `0.0.0.0`, not `127.0.0.1` — on purpose: loopback
measurements only tell you sidecheck's pipeline works, not whether a leak
is detectable over an actual network path (real jitter, real packet loss).
Run one on a VPS you control, then run `sidecheck doctor`/`check` against
it from a *different* machine — the whole point is to force requests
through a real network path, so running the client on the same box as the
fixture (even against its public IP) defeats the purpose and can behave
oddly depending on the provider's hairpin NAT support.

This does mean the endpoint is reachable from the whole internet while
it's running — it's a deliberately timing-vulnerable test endpoint with a
throwaway secret, so the risk is low, but two things are worth doing
anyway: don't leave it running longer than the test session, and restrict
inbound access to just your own IP rather than the world, e.g.:

```sh
ufw allow from <your-IP> to any port 8001 proto tcp
```

(scan/bot traffic hitting the port while you measure would also just add
noise to the timing data, so this helps the measurement too, not only
security.)

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

## json_login_fixture.py

Pure Python, no dependencies. Exercises `--json-body` (0.2.0): a realistic
`/login` that needs a `username` besides the password to even reach the
secret comparison — the case `--json-field` alone can't cover, since it
only ever sends `{"password": "..."}`.

```sh
python3 json_login_fixture.py
# serves on http://127.0.0.1:8003
#   /vulnerable — manual character-by-character comparison, amplified delay
#   /safe       — hmac.compare_digest

sidecheck check http://127.0.0.1:8003/vulnerable \
  --json-field password --json-body '{"username": "admin"}' \
  --secret correct-secret-key-123456
```

## csrf_header_fixture.py

Pure Python, no dependencies. Exercises `--extra-header`: a realistic
endpoint gated by a CSRF token header on top of the value under test —
the header equivalent of what `json_login_fixture.py` covers for JSON
bodies. Without the token, every request gets `403` before the API key
comparison is even reached.

```sh
python3 csrf_header_fixture.py
# serves on http://127.0.0.1:8004
#   /vulnerable — manual character-by-character comparison, amplified delay
#   /safe       — hmac.compare_digest

sidecheck check http://127.0.0.1:8004/vulnerable \
  --header X-API-Key --extra-header "X-CSRF-Token=expected-csrf-token" \
  --secret correct-secret-key-123456
```

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
