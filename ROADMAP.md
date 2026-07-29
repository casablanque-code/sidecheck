# sidecheck — roadmap

## Shipped

- `check` / `doctor` core pipeline, box test + bootstrap CI, MAD-based
  jitter estimate, pilot-based feasibility guard
- Header / query param / JSON body field injection, `--json-body`
  templates for realistic multi-field login endpoints, `--extra-header`
  for CSRF tokens/session cookies the endpoint needs before reaching the
  value under test
- `--repeat` stability summaries, `--seed` reproducibility,
  `--report`/`--output-csv` for CI
- Published to crates.io (`sidecheck-core`, `sidecheck`), automated
  release pipeline (tag → publish crates + build binaries → GitHub
  Release)
- MSRV declared (`rust-version = "1.85"`), `cargo install --locked`
  documented as the safe install path
- CI runs live `check`/`doctor` end-to-end against the amplified Python
  fixture (positive/negative cases, `--json-body` injection and its
  argument-validation regressions), in addition to fmt/clippy/unit tests
- `sidecheck compare baseline.json current.json` — flags a new leak
  relative to a baseline report without failing on a pre-existing one
- A composite GitHub Action (`action/`) wrapping the binary: runs
  `check` (and `compare` if a baseline is given), posts/updates a PR
  comment, sets outputs, fails the step per `fail-on-leak`/
  `fail-on-regression`. Self-tested in CI against a live fixture
  (positive, negative, regression, and invalid-input cases)

## Next: wiring the Action into a full CI gate

The Action itself is done — what's still missing is the piece that
turns it into the full picture from the original pitch:

```
PR opened
  ↓
deploy preview / ephemeral environment comes up
  ↓
sidecheck-action runs against the preview URL (with baseline-report set)
  ↓
timing regression introduced?
  ↓
block merge — PR comment already shows the report
```

- [ ] A documented, tested reference pattern for baseline storage
      specifically — `action/examples/pr-gate.yml` sketches one approach
      (`actions/cache` keyed on the base branch), but it's an example,
      not something exercised in this repo's own CI the way the rest of
      the Action is
- [ ] `cargo sidecheck` subcommand as a friendlier local entry point,
      mirroring how `cargo audit`/`cargo clippy` feel native to a Rust
      workflow even though the actual logic doesn't care about Cargo at
      all
- [ ] Marketplace listing once the Action has real external usage to
      point to, rather than just this repo's own self-test

## Also planned

- [ ] Reference target fixtures for FastAPI, Express, Actix, Axum, Spring
      — currently only Go and Node have non-amplified reference fixtures
- [ ] A documented secret-length sweep finding the crossover point where
      a real (non-amplified) leak becomes reliably detectable over actual
      HTTP, as a data point rather than something every user has to
      rediscover themselves
- [ ] CI coverage of the Go/Node realistic fixtures specifically —
      currently only the amplified Python fixture runs in CI (installing
      go/node toolchains in the e2e job is the remaining work)
- [ ] Shared-prime-factor detection via batch-GCD across a fleet of keys
      — a different vulnerability class entirely, kept separate from
      timing analysis, but a natural next audit to bolt onto the same CLI
