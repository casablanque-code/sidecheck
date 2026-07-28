# Statistics reference

The exact math behind `sidecheck`'s output. See
[methodology.md](./methodology.md) for the reasoning behind the approach;
this page is the formulas.

## Jitter estimate (MAD-based)

Network jitter is estimated from a pilot sample using the **median
absolute deviation (MAD)** from the median, not variance/standard
deviation:

```
mad = median(|x_i - median(x)|)
jitter ≈ mad * 1.4826
```

The 1.4826 multiplier is the standard factor that makes MAD a consistent
estimator of standard deviation for normally distributed data.

This matters because variance is extremely sensitive to single outliers —
the first request after a TCP connection is established, a GC pause, an
OS scheduling hiccup. One slow request out of three hundred can inflate a
variance-based jitter estimate several times over, which previously meant
two independent measurements of the same stable channel (`doctor` vs
`check`'s own pilot) could disagree by 5x. MAD requires corrupting more
than half the sample to move the median, so a single outlier barely
budges it.

## Required sample size

Both `doctor`'s `recommended samples` and `check`'s pre-flight guard use
the same formula, from power analysis for comparing two means:

```
n ≈ 2 * (z_alpha/2 + z_beta)^2 * jitter^2 / leak^2
```

- `z_alpha/2` — the z-value for a two-sided test at the requested
  confidence level (1.96 for 95% confidence)
- `z_beta` — fixed at 0.84, corresponding to 80% statistical power
- `jitter` — the MAD-based jitter estimate above
- `leak` — the effect size to detect. `doctor` doesn't have a real
  measurement to work from yet, so it uses a fixed ~1μs reference point
  (a conservative estimate of what a real, uninflated `==` vs
  constant-time gap costs in compiled code). `check` uses the actual
  effect size from its own pilot batch once it has one.

This is why `doctor`'s recommended sample count can look enormous even on
a "GOOD" quality path: at 0.42ms of jitter and a 1μs target leak, the
formula gives roughly 2.77 million samples. That's not a bug — a 1μs
signal genuinely is that hard to resolve behind millisecond-scale network
noise. `GOOD` means the estimate itself is trustworthy, not that the run
will be fast.

## Box test and bootstrap confidence interval

```
leak_estimate = percentile(class_b, p) - percentile(class_a, p)
```

where `p` is the low percentile (10 by default, `--percentile`). The
confidence interval around that difference is built via **bootstrap
resampling**: the raw class A and class B samples are resampled with
replacement thousands of times (2000 by default), the same percentile
difference is computed for each resample, and the interval is read off
the empirical distribution of those differences. This makes no assumption
about the underlying distribution being normal, which network latency
generally isn't.

A result is flagged as a **statistically significant leak** exactly when
this confidence interval doesn't contain zero.

`bootstrap confidence` in the report is the confidence level of that
interval — it answers "how sure are we this specific difference isn't
just noise," not "what's the probability this server is vulnerable," and
it isn't a p-value in the classical hypothesis-testing sense.

## Stability across `--repeat` runs

With `--repeat N`, `sidecheck` runs the full pilot+measurement cycle N
times and reports two things: whether the significance verdict is
consistent (0/N or N/N) and, only if it's consistent, how much the point
estimate itself varies (mean, range, standard deviation).

Significance agreement is checked first and weighted more heavily than
raw variance of the estimate on purpose: when there's genuinely no leak,
the mean estimate sits near zero, and any tiny absolute wobble produces a
huge *relative* standard deviation — a statistical artifact of dividing by
approximately zero, not a real instability. Mixed significance across
runs (some flag a leak, some don't) is the case actually worth
distrusting; it usually means the effect sits right at the edge of what
the sample size can resolve.
