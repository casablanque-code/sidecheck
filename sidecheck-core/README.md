# sidecheck-core

Library crate behind [`sidecheck`](https://crates.io/crates/sidecheck), a
remote timing side-channel auditor. If you're looking for the CLI tool,
see that crate instead — this one is for embedding the same detection
logic in your own Rust code (a custom test harness, a CI check, a
different transport than HTTP, etc.).

## What's in here

- **`stats`** — the statistical core. `box_test` compares the low
  percentile of two timing samples (methodology from Crosby, Wallach &
  Riedi, *"Opportunities and Limits of Remote Timing Attacks"*, ACM
  TISSEC 2009), with a bootstrap-resampled confidence interval rather
  than an assumption of normally-distributed network latency.
  `estimate_jitter` gives a robust (MAD-based, outlier-resistant) noise
  estimate, and `required_samples` does the power-analysis math to size a
  run before you commit to it.
- **`sampler`** *(feature `http`, default on)* — an HTTP-based sampler:
  `HttpTarget` plus `run_interleaved`, which measures two classes of
  request in randomized interleaved blocks (never "all A, then all B") to
  avoid confounding the result with time-of-day drift or server warm-up.
  Requires `reqwest`; disable the `http` feature (`default-features =
  false`) if you only need the statistics and want to supply your own
  timing measurements.
- **`doctor`** — pre-flight network-quality diagnostics (median RTT,
  jitter classification, packet loss, a recommended sample count) built
  on `stats` alone, with no HTTP dependency of its own.
- **`report`** / **`export`** — human-readable and machine-readable
  (JSON/CSV) report formatting.

## Example: statistics only, your own timing source

```rust
use sidecheck_core::stats::box_test;

// two vectors of measured elapsed seconds, however you collected them
let class_a: Vec<f64> = vec![0.001, 0.0011, 0.00105, 0.00098, 0.00102];
let class_b: Vec<f64> = vec![0.0015, 0.0016, 0.00155, 0.00148, 0.00152];

let result = box_test(&class_a, &class_b, /* low_percentile */ 10.0, /* confidence */ 0.95);
if result.is_significant() {
    println!("leak: {:.1} us", result.estimated_leak.abs() * 1_000_000.0);
}
```

## Example: HTTP sampling (default `http` feature)

```rust,no_run
use sidecheck_core::sampler::{HttpTarget, InjectionPoint, run_interleaved, random_wrong_value};
use rand::{SeedableRng, rngs::StdRng};

# fn main() -> anyhow::Result<()> {
let target = HttpTarget::new(
    "https://myapp.local/login",
    InjectionPoint::Header("X-API-Key".into()),
)?;
let secret = "the-real-secret";
let mut rng = StdRng::seed_from_u64(42);
let wrong = random_wrong_value(secret, &mut rng);

let raw = run_interleaved(&target, &wrong, secret, 5_000, 20, &mut rng, |_, _| {})?;
# Ok(())
# }
```

## Limitations

Same as the CLI: this can detect a statistically significant timing
difference under the tested conditions. It cannot prove one doesn't
exist. See the [main README](https://github.com/casablanque-code/sidecheck#limitations)
for the full discussion, including why a real (non-amplified) timing leak
is often *not* reliably detectable over an actual HTTP round-trip even
when it's real at the CPU level.

## License

MIT
