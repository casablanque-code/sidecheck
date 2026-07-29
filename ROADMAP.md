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

## Next: killer feature — a GitHub Action

Right now `sidecheck` is a CLI you run by hand. The bigger opportunity is
turning it into a CI gate, the same way `cargo audit` or a coverage
threshold check works today:

```
PR opened
  ↓
deploy preview / ephemeral environment comes up
  ↓
sidecheck-action runs against the preview URL
  ↓
timing regression introduced?
  ↓
block merge, comment on the PR with the report
```

This is a genuinely new category of CI check — most security scanning is
static (SAST) or dependency-based (SCA); a timing-regression gate on a
live preview environment doesn't have an established competitor. Rough
shape:

- [ ] `sidecheck-action` — a composite GitHub Action wrapping the binary,
      inputs for target URL / injection point / secret (via GitHub
      Secrets) / max acceptable run time
- [ ] Structured PR comment output (reuse `--report` JSON, render as a
      readable comment via the Action, not just raw CLI text in logs)
- [ ] Baseline storage and wiring for CI — `sidecheck compare` (shipped)
      already does the actual regression logic given two report files;
      what's still missing is fetching/storing the base branch's report
      between CI runs (repo file vs. Actions cache vs. artifact from the
      base branch's own run — undecided, see
      [docs/reproducibility.md](./docs/reproducibility.md#comparing-against-a-baseline))
- [ ] `cargo sidecheck` subcommand as a friendlier local entry point,
      mirroring how `cargo audit`/`cargo clippy` feel native to a Rust
      workflow even though the actual logic doesn't care about Cargo at
      all

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
