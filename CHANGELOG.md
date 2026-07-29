# Changelog

Format based on [Keep a Changelog](https://keepachangelog.com/), versions per [SemVer](https://semver.org/).

## [Unreleased]

### Added
- `--extra-header` — sends a static header unchanged on every request (repeatable, `NAME=VALUE`), for CSRF tokens/session cookies/other auth layers the endpoint needs before it reaches the value under test. Available on both `check` and `doctor`.

## [0.2.1] — 2026-07-27

### Fixed
- `--json-body` without `--json-field` was silently ignored instead of rejected — clap's `requires` attribute doesn't fire reliably when the target arg is also a member of an `ArgGroup`. Replaced with an explicit manual check and a clear error message.
- `sidecheck-cli` was missing a direct `serde_json` dependency (it only had it transitively via `sidecheck-core`) — broke `cargo build`/`clippy` for anyone building from a fresh checkout.
- Release automation: the tag pushed by `Prepare Release` didn't trigger `Release`, because GitHub deliberately excludes `GITHUB_TOKEN`-authored pushes from triggering other workflows. `Prepare Release` now checks out with a `RELEASE_PAT` secret so the tag push counts as external; `Release` also gained a `workflow_dispatch` fallback so a stuck tag can be resumed without re-tagging.
- `softprops/action-gh-release` needs an explicit `tag_name` on `workflow_dispatch` runs, since `GITHUB_REF` points at the branch, not the tag, in that case.

## [0.2.0] — 2026-07-27

### Added
- `--json-body` — a request body template for `--json-field`, so the rest of the required fields (username, email, etc.) that the backend needs to reach the secret comparison can be supplied
- `rust-version` (MSRV) in Cargo.toml + a dedicated CI job building the workspace at the declared MSRV, so a regression on that boundary is caught in CI instead of by a user running `cargo install`
- Release automation: `Prepare Release` (manual trigger, bumps version/tag) → `Release` (publishes sidecheck-core and sidecheck to crates.io idempotently, builds linux/macos/windows binaries, creates a GitHub Release)

### Fixed
- README: the `cargo install` command now uses `--locked`, to use the committed Cargo.lock instead of re-resolving dependencies — works around `feature edition2024 is required` on older system toolchains (e.g. Ubuntu 24.04 LTS's packaged cargo 1.75)

### Changed
- Clarified the `sidecheck doctor` wording: `recommended samples` is a power-analysis estimate for comparing means (using MAD-based jitter as a proxy), not an exact box-test/bootstrap power calculation; a fixed ~1μs condition is used as the reference point

## [0.1.0] — retroactive, no formal GitHub release was cut at the time

First working version. Added to the changelog after the fact, once sidecheck-core and sidecheck were published to crates.io.

### Added
- `sidecheck check` — box test (Crosby–Wallach–Riedi) with bootstrap confidence intervals on the low percentile (p10 by default), randomized block interleaving of classes, automatic sample-count selection from a pilot run
- Value injection into a header / query param / a single JSON body field
- Ways to supply the secret: `--secret`, `--secret-env`, `--secret-stdin` (with a warning about `--secret` being visible in `ps aux`/history)
- `sidecheck doctor` — pre-flight network check (median RTT, jitter, packet loss, recommended sample count, environment classification)
- MAD-based (outlier-robust) jitter estimate — replaced an earlier variance-based one
- `--repeat N` — repeated full runs to check result stability
- Raw data export to CSV and a machine-readable JSON report (`--report`) for CI
- `--seed` for reproducible request interleaving order
- A guard against a run that's doomed from the start: if the jitter estimate says even `--max-samples` won't have enough power, sidecheck stops early (override with `--force`)
- E2E CI against a real fixture server (Python), unit tests for the statistics, cargo-audit, Dependabot
- Documented limitation: a ~25-byte leak isn't detectable over the public internet (jitter masks the effect)
