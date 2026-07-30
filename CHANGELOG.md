# Changelog

Format based on [Keep a Changelog](https://keepachangelog.com/), versions per [SemVer](https://semver.org/).

## [0.3.0] — 2026-07-30

### Added
- `--extra-header` — sends a static header unchanged on every request (repeatable, `NAME=VALUE`), for CSRF tokens/session cookies/other auth layers the endpoint needs before it reaches the value under test. Available on both `check` and `doctor`.
- `sidecheck compare baseline.json current.json` — flags a *new* leak relative to a baseline report (exits 1 only when the baseline was clean and the current run isn't), rather than failing on any leak including pre-existing ones. Building block for a CI regression gate.
- A composite GitHub Action (`action/`) wrapping the binary — runs `check` (and `compare` against a baseline if given), posts/updates a PR comment, exposes `significant`/`estimated-leak-us`/`regression`/`report-path` as outputs. See `action/README.md`.
- Colorized terminal output for `check`/`doctor`/`compare`/the `--repeat` stability summary — headers, ✓/⚠/✗ verdict marks, and highlighted numbers, via the `console` crate. Automatically drops to plain text when NO_COLOR is set or output isn't a terminal (piped/CI), so machine-parsed output and log files are unaffected. Warnings and fatal errors now go through consistent `warning:`/`error:` (+ `hint:`) formatting instead of ad-hoc `eprintln!`s.

### Fixed
- Two negative-case assertions in the e2e CI job (`check` should stay quiet on a genuinely safe endpoint) had an inherent ~5% false-positive rate from running sidecheck's own 95%-confidence bootstrap test as a hard CI assertion — raised to `--confidence 0.999` for those specific checks. A separate assertion that was really testing a deterministic protocol fact (a missing username short-circuits before the password comparison) was replaced with a direct `curl` check instead of relying on statistical inference for something that isn't actually random.

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
