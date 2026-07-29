# Usage details

## Handling secrets

`--secret` is convenient but shows up in `ps aux` and your shell history —
fine for a throwaway test key, not for anything real. Prefer:

```sh
# from an environment variable
sidecheck check https://myapp.local/login --header X-API-Key --secret-env API_KEY

# piped from stdin (e.g. from a password manager)
pass show myapp/api-key | sidecheck check https://myapp.local/login --header X-API-Key --secret-stdin
```

`sidecheck` itself never sends your secret anywhere except the target you
told it to test, and never logs it to disk. It does **not** attempt to
scrub `--secret` from your shell's history file — from a child process
there's no reliable, portable way to do that (the shell keeps history in
memory until it writes the file on exit, and the format differs between
bash/zsh/fish). Use `--secret-env`/`--secret-stdin` instead of trying to
clean up after the fact.

## Advanced mode

Full control over both compared values, e.g. to test a specific guessed
prefix instead of the full secret:

```sh
sidecheck check https://myapp.local/login \
  --header X-API-Key \
  --value-a "0000000000000000000000000" \
  --value-b "correct-se0000000000000000" \
  --samples 5000
```

Combine with `--extra-header` for endpoints that need a CSRF token or
session cookie before this comparison is even reached — see the main
README for the basic case.

## When sidecheck refuses to run

If the pilot batch estimates the network is too noisy relative to the
detected effect to reach significance within `--max-samples` (200,000 by
default), `sidecheck check` stops **before** the main run instead of
silently spending minutes-to-hours on a result that would almost
certainly be inconclusive. It explains the signal-to-noise ratio and the
estimated wall-clock time it would have taken. Options at that point:

- test from a lower-latency vantage point (same LAN/datacenter as the
  target, or the server itself over `127.0.0.1`) — `sidecheck doctor`
  will confirm whether that's actually better before you commit to it
- pass `--force` if you understand the run will likely be inconclusive
  and want the data anyway
- raise `--max-samples` if you're willing to wait longer

`--samples` set explicitly bypasses this gate (you've already made the
call) but still prints the same time/power estimate as a heads-up.

Full flag reference: `sidecheck check --help` / `sidecheck doctor --help`
— tuning knobs like `--pilot-samples`, `--block-size`, `--confidence`, and
`--percentile` are documented there rather than duplicated here, since
duplicating them in prose is exactly how documentation quietly goes
stale.
