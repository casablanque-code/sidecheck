//! Statistical core of sidecheck.
//!
//! Methodology based on Crosby, Wallach, Riedi, "Opportunities and Limits
//! of Remote Timing Attacks" (ACM TISSEC, 2009): the network can only add
//! delay, never remove it, so the low percentiles of a sample carry far
//! less noise than the mean or even the raw minimum. This is what the
//! "box test" builds on — comparing the low percentiles of two samples.

/// Number of bootstrap resampling iterations for the confidence interval.
/// Pulled out into a constant so it can be reported honestly — not just
/// "confidence: 95%", but explicitly "bootstrap confidence over N
/// iterations".
pub const BOOTSTRAP_ITERATIONS: usize = 2000;

use rand::Rng;

/// Returns the p-th percentile of a sorted sample (p in [0.0, 100.0]).
pub fn percentile(sorted: &[f64], p: f64) -> f64 {
    assert!(!sorted.is_empty(), "empty sample");
    let idx = (p / 100.0 * (sorted.len() - 1) as f64).round() as usize;
    sorted[idx.min(sorted.len() - 1)]
}

fn sorted_copy(data: &[f64]) -> Vec<f64> {
    let mut v = data.to_vec();
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    v
}

/// Result of a box test: the difference between the low percentiles of two
/// samples, plus a confidence interval obtained via bootstrap (no
/// assumption of normally-distributed network latency).
#[derive(Debug, Clone)]
pub struct BoxTestResult {
    pub class_a_low_percentile: f64,
    pub class_b_low_percentile: f64,
    /// class_b - class_a, in the same units as the input data (seconds)
    pub estimated_leak: f64,
    pub ci_low: f64,
    pub ci_high: f64,
    pub confidence: f64,
}

impl BoxTestResult {
    /// The leak is considered statistically significant if the confidence
    /// interval of the difference does not contain zero.
    pub fn is_significant(&self) -> bool {
        self.ci_low > 0.0 || self.ci_high < 0.0
    }
}

/// Box test per the Crosby-Wallach methodology: compares the low
/// percentile (p10 by default) of two response-time samples; the
/// confidence interval is built via bootstrap resampling.
pub fn box_test(
    class_a: &[f64],
    class_b: &[f64],
    low_percentile: f64,
    confidence: f64,
) -> BoxTestResult {
    let a_sorted = sorted_copy(class_a);
    let b_sorted = sorted_copy(class_b);

    let a_p = percentile(&a_sorted, low_percentile);
    let b_p = percentile(&b_sorted, low_percentile);
    let leak = b_p - a_p;

    let (ci_low, ci_high) = bootstrap_ci(
        class_a,
        class_b,
        low_percentile,
        confidence,
        BOOTSTRAP_ITERATIONS,
    );

    BoxTestResult {
        class_a_low_percentile: a_p,
        class_b_low_percentile: b_p,
        estimated_leak: leak,
        ci_low,
        ci_high,
        confidence,
    }
}

/// Bootstrap confidence interval for the difference between low
/// percentiles. Doesn't rely on normality — resamples the raw data with
/// replacement and builds the empirical distribution of the difference.
fn bootstrap_ci(
    class_a: &[f64],
    class_b: &[f64],
    p: f64,
    confidence: f64,
    iterations: usize,
) -> (f64, f64) {
    let mut rng = rand::thread_rng();
    let mut diffs = Vec::with_capacity(iterations);

    for _ in 0..iterations {
        let resample_a = resample(class_a, &mut rng);
        let resample_b = resample(class_b, &mut rng);
        let pa = percentile(&sorted_copy(&resample_a), p);
        let pb = percentile(&sorted_copy(&resample_b), p);
        diffs.push(pb - pa);
    }

    diffs.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let alpha = 1.0 - confidence;
    let lo_idx = ((alpha / 2.0) * diffs.len() as f64) as usize;
    let hi_idx = (((1.0 - alpha / 2.0) * diffs.len() as f64) as usize).min(diffs.len() - 1);
    (diffs[lo_idx], diffs[hi_idx])
}

fn resample(data: &[f64], rng: &mut impl Rng) -> Vec<f64> {
    (0..data.len())
        .map(|_| data[rng.gen_range(0..data.len())])
        .collect()
}

/// Estimates network jitter from a pilot sample. Used to be computed as
/// the standard deviation around the low percentile — but variance
/// (squared deviations) is extremely sensitive to single outliers (the
/// first request after connection setup, a GC pause, OS scheduling): one
/// slow request out of three hundred could inflate the estimate several
/// times over, which is why two independent measurements of the same
/// channel could disagree wildly.
///
/// MAD (median absolute deviation from the median) is nearly insensitive
/// to single outliers: shifting the median requires corrupting more than
/// half the sample, not one request. The 1.4826 multiplier is the
/// standard factor that makes MAD a consistent estimator of standard
/// deviation for normally distributed data.
pub fn estimate_jitter(pilot: &[f64]) -> f64 {
    if pilot.is_empty() {
        return 0.0;
    }
    let sorted = sorted_copy(pilot);
    let median = percentile(&sorted, 50.0);
    let mut abs_deviations: Vec<f64> = pilot.iter().map(|x| (x - median).abs()).collect();
    abs_deviations.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let mad = percentile(&abs_deviations, 50.0);
    mad * 1.4826
}

/// Estimates the minimum number of requests per class needed to detect a
/// leak of the given size at the given network noise level. Formula from
/// power analysis for comparing means:
/// n ≈ 2 * (z_alpha/2 + z_beta)^2 * sigma^2 / delta^2
pub fn required_samples(jitter: f64, expected_leak_seconds: f64, confidence: f64) -> u64 {
    if expected_leak_seconds <= 0.0 {
        return u64::MAX;
    }
    // z-values for a two-sided test at `confidence` with 80% power (z_beta ≈ 0.84)
    let z_alpha = inverse_normal_cdf(1.0 - (1.0 - confidence) / 2.0);
    let z_beta = 0.84;
    let n = 2.0 * (z_alpha + z_beta).powi(2) * jitter.powi(2) / expected_leak_seconds.powi(2);
    n.ceil() as u64
}

/// Approximation of the inverse normal CDF (Beasley-Springer-Moro).
/// Accurate enough for estimating the required sample size.
fn inverse_normal_cdf(p: f64) -> f64 {
    // Rational approximation, maximum error ~1.15e-9
    let a = [
        -3.969683028665376e+01,
        2.209460984245205e+02,
        -2.759285104469687e+02,
        1.383_577_518_672_69e2,
        -3.066479806614716e+01,
        2.506628277459239e+00,
    ];
    let b = [
        -5.447609879822406e+01,
        1.615858368580409e+02,
        -1.556989798598866e+02,
        6.680131188771972e+01,
        -1.328068155288572e+01,
    ];
    let c = [
        -7.784894002430293e-03,
        -3.223964580411365e-01,
        -2.400758277161838e+00,
        -2.549732539343734e+00,
        4.374664141464968e+00,
        2.938163982698783e+00,
    ];
    let d = [
        7.784695709041462e-03,
        3.224671290700398e-01,
        2.445134137142996e+00,
        3.754408661907416e+00,
    ];
    let p_low = 0.02425;
    let p_high = 1.0 - p_low;

    if p < p_low {
        let q = (-2.0 * p.ln()).sqrt();
        (((((c[0] * q + c[1]) * q + c[2]) * q + c[3]) * q + c[4]) * q + c[5])
            / ((((d[0] * q + d[1]) * q + d[2]) * q + d[3]) * q + 1.0)
    } else if p <= p_high {
        let q = p - 0.5;
        let r = q * q;
        (((((a[0] * r + a[1]) * r + a[2]) * r + a[3]) * r + a[4]) * r + a[5]) * q
            / (((((b[0] * r + b[1]) * r + b[2]) * r + b[3]) * r + b[4]) * r + 1.0)
    } else {
        let q = (-2.0 * (1.0 - p).ln()).sqrt();
        -(((((c[0] * q + c[1]) * q + c[2]) * q + c[3]) * q + c[4]) * q + c[5])
            / ((((d[0] * q + d[1]) * q + d[2]) * q + d[3]) * q + 1.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn percentile_basic() {
        let data = vec![1.0, 2.0, 3.0, 4.0, 5.0];
        assert_eq!(percentile(&data, 0.0), 1.0);
        assert_eq!(percentile(&data, 100.0), 5.0);
        assert_eq!(percentile(&data, 50.0), 3.0);
    }

    #[test]
    fn jitter_estimate_is_robust_to_a_single_outlier() {
        // Regression for a real bug found in the wild: two independent
        // measurements of the same stable channel (doctor vs check pilot)
        // disagreed by 5x, because the old (variance-based) jitter
        // estimate was disproportionately sensitive to a single slow
        // request (e.g. the first one after TCP connection setup).
        let mut stable: Vec<f64> = (0..300)
            .map(|i| 0.0002 + (i as f64 % 5.0) * 0.00001)
            .collect();
        let jitter_without_outlier = estimate_jitter(&stable);

        // a single request suddenly took 50ms instead of ~0.2ms
        stable[0] = 0.050;
        let jitter_with_outlier = estimate_jitter(&stable);

        // MAD should not spike several times over from one outlier out of
        // 300 samples — the old variance-based implementation blew up by
        // tens of times here
        assert!(
            jitter_with_outlier < jitter_without_outlier * 3.0,
            "a single outlier out of 300 samples should not blow up the jitter \
             estimate this much: {jitter_without_outlier} -> {jitter_with_outlier}"
        );
    }

    #[test]
    fn box_test_detects_no_difference() {
        let a: Vec<f64> = (0..1000)
            .map(|i| 0.010 + (i as f64 % 7.0) * 0.0001)
            .collect();
        let b = a.clone();
        let result = box_test(&a, &b, 10.0, 0.95);
        assert!(
            !result.is_significant(),
            "identical samples must not be significant"
        );
    }

    #[test]
    fn box_test_detects_real_difference() {
        let a: Vec<f64> = (0..2000)
            .map(|i| 0.010 + (i as f64 % 11.0) * 0.0002)
            .collect();
        let b: Vec<f64> = (0..2000)
            .map(|i| 0.010 + 0.0005 + (i as f64 % 11.0) * 0.0002)
            .collect();
        let result = box_test(&a, &b, 10.0, 0.95);
        assert!(
            result.is_significant(),
            "clear 0.5ms shift must be detected"
        );
        assert!(result.estimated_leak > 0.0);
    }
}
