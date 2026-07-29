# sidecheck GitHub Action

Wraps the `sidecheck` binary as a composite GitHub Action — audit an HTTP
endpoint for a timing side-channel as part of CI, and optionally fail the
build only when a change introduces a **new** leak rather than any leak
at all.

See the main [README](../README.md) and [docs/](../docs/) for what
sidecheck actually measures and its limitations before wiring this into
a merge gate — a clean result here is not a safety guarantee, and this
Action doesn't change that.

## Quick start

```yaml
- uses: casablanque-code/sidecheck/action@v0.2.1
  with:
    target-url: https://preview.example.com/login
    header: X-API-Key
    secret: ${{ secrets.SIDECHECK_TEST_KEY }}
```

Pin a specific release tag (`@v0.2.1`), not `@main` — `version: latest`
as an input only controls which sidecheck *binary* gets downloaded, it
doesn't protect you from the Action's own YAML changing under you.

## With a baseline (recommended for a merge gate)

Without `baseline-report`, the Action fails on *any* significant leak —
useful for a one-off audit, but noisy as a permanent CI gate if the
endpoint already has a known, tracked issue you're not fixing in this PR.
With a baseline, it fails only on a *new* one:

```yaml
- uses: casablanque-code/sidecheck/action@v0.2.1
  with:
    target-url: https://preview.example.com/login
    header: X-API-Key
    secret: ${{ secrets.SIDECHECK_TEST_KEY }}
    baseline-report: sidecheck-baseline.json
```

Getting `sidecheck-baseline.json` onto disk before this step (from the
base branch's last run) is on you — this Action deliberately doesn't
decide that for you, since it depends on your CI setup (cache, artifact,
a committed file, a separate storage step). See
[examples/pr-gate.yml](./examples/pr-gate.yml) for one complete pattern
using `actions/cache`, and
[docs/reproducibility.md](../docs/reproducibility.md#comparing-against-a-baseline)
for the underlying `sidecheck compare` semantics this Action calls.

## Inputs

| Input | Required | Default | Description |
|---|---|---|---|
| `target-url` | yes | | Endpoint to check |
| `secret` | yes | | The real secret value — pass via `secrets.*`, never a literal |
| `header` / `query` / `json-field` | one required | | Injection point (exactly one) |
| `json-body` | no | | JSON template for the rest of the body (needs `json-field`) |
| `extra-headers` | no | | Static headers, one `NAME=VALUE` per line (CSRF tokens, cookies) |
| `samples` | no | auto | Fixed sample count, otherwise auto-selected |
| `confidence` | no | `0.95` | Confidence level |
| `max-samples` | no | `200000` | Ceiling for auto-selected sample count |
| `insecure` | no | `false` | Accept self-signed TLS certs |
| `force` | no | `false` | Proceed even if the pilot run looks infeasible |
| `version` | no | `latest` | sidecheck release to install — pin this |
| `baseline-report` | no | | Path to a previous JSON report to compare against |
| `fail-on-leak` | no | `true` | Fail if significant, when no baseline is given |
| `fail-on-regression` | no | `true` | Fail if `compare` reports a new regression, when a baseline is given |
| `comment-on-pr` | no | `true` | Post/update a PR comment with the result |
| `github-token` | no | `github.token` | Token for posting the PR comment |

## Outputs

| Output | Description |
|---|---|
| `significant` | `"true"`/`"false"` — this run's own verdict |
| `estimated-leak-us` | Estimated leak in microseconds |
| `regression` | `"true"`/`"false"` — only set if `baseline-report` was given |
| `report-path` | Path to this run's JSON report — upload/cache it as the next baseline |

## What this Action doesn't do (yet)

- Only Linux, macOS, and Windows `x86_64`/`aarch64` runners are supported
  (whatever `sidecheck`'s release binaries cover) — there's no source
  build fallback.
- No baseline storage/fetching — see above.
- One target per step. Auditing several endpoints means several steps.
