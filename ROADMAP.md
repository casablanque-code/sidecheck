# sidecheck — roadmap

## Shipped

- `check` / `doctor` core pipeline, box test + bootstrap CI, MAD-based
  jitter estimate, pilot-based feasibility guard
- Header / query param / JSON body field injection, `--json-body`
  templates for realistic multi-field login endpoints
- `--repeat` stability summaries, `--seed` reproducibility,
  `--report`/`--output-csv` for CI
- Published to crates.io (`sidecheck-core`, `sidecheck`), automated
  release pipeline (tag → publish crates + build binaries → GitHub
  Release)
- MSRV declared (`rust-version = "1.85"`), `cargo install --locked`
  documented as the safe install path

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
- [ ] A documented pattern for baseline comparison — flag a *regression*
      (new leak that wasn't there in the base branch), not just any leak,
      since re-running the full statistical suite on every PR against an
      absolute threshold is noisier than comparing against a stored
      baseline
- [ ] `cargo sidecheck` subcommand as a friendlier local entry point,
      mirroring how `cargo audit`/`cargo clippy` feel native to a Rust
      workflow even though the actual logic doesn't care about Cargo at
      all

## Also planned

- [ ] Auth headers beyond the secret under test (Bearer/Cookie/CSRF
      token) — many real login endpoints need a CSRF token or session
      cookie before the password comparison is even reached, similar to
      the `--json-body` gap that 0.2.0 closed for the JSON case
- [ ] Reference target fixtures for FastAPI, Express, Actix, Axum, Spring
      — currently only Go and Node have non-amplified reference fixtures
- [ ] A documented secret-length sweep finding the crossover point where
      a real (non-amplified) leak becomes reliably detectable over actual
      HTTP, as a data point rather than something every user has to
      rediscover themselves
- [ ] CI coverage of the actual detection logic against a live fixture
      end-to-end (current CI runs fmt/clippy/unit tests, not a real
      `check`-against-a-fixture pass)
- [ ] Shared-prime-factor detection via batch-GCD across a fleet of keys
      — a different vulnerability class entirely, kept separate from
      timing analysis, but a natural next audit to bolt onto the same CLI
