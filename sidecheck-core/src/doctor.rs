//! `sidecheck doctor` is a measurement feasibility estimator: a fast
//! pre-flight check of the path to the target, run BEFORE spending time on
//! a full test. It answers "is it even worth trying to measure a timing
//! leak over this path", not "is there a leak".

use crate::stats::{estimate_jitter, percentile, required_samples};

/// A conservative size for a "typical" real leak from an unsafe
/// comparison — not artificially amplified, but the kind of gap that
/// `==` instead of a constant-time comparison actually produces in real
/// compiled code: single-digit microseconds. Only used to give a
/// meaningful sample-count recommendation BEFORE we have a real effect
/// size from check's pilot run — doctor itself doesn't compare anything,
/// it has no real effect size to draw on.
const TYPICAL_LEAK_SECONDS: f64 = 1e-6;

pub struct DoctorReport {
    pub target: String,
    pub samples: usize,
    pub median_rtt_seconds: f64,
    pub jitter_seconds: f64,
    pub packet_loss_ratio: f64,
    pub recommended_samples: u64,
}

#[derive(Debug, PartialEq, Eq)]
pub enum JitterLevel {
    Low,
    Medium,
    High,
}

impl JitterLevel {
    fn label(&self) -> &'static str {
        match self {
            JitterLevel::Low => "low",
            JitterLevel::Medium => "medium",
            JitterLevel::High => "high",
        }
    }
}

/// Rough jitter classification. Thresholds picked from practice: under 1ms
/// is local network/loopback, single-digit milliseconds is same
/// datacenter or a good LAN, tens of milliseconds is typical public
/// internet.
fn classify_jitter(jitter_seconds: f64) -> JitterLevel {
    if jitter_seconds < 0.001 {
        JitterLevel::Low
    } else if jitter_seconds < 0.010 {
        JitterLevel::Medium
    } else {
        JitterLevel::High
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum EnvironmentQuality {
    Good,
    Fair,
    Poor,
}

impl EnvironmentQuality {
    fn label(&self) -> &'static str {
        match self {
            EnvironmentQuality::Good => "GOOD",
            EnvironmentQuality::Fair => "FAIR",
            EnvironmentQuality::Poor => "POOR",
        }
    }
}

impl DoctorReport {
    pub fn from_measurements(target: String, latencies: &[f64], failures: usize) -> Self {
        let samples = latencies.len();
        let attempted = samples + failures;
        let packet_loss_ratio = if attempted > 0 {
            failures as f64 / attempted as f64
        } else {
            1.0
        };

        let mut sorted = latencies.to_vec();
        sorted.sort_by(|a, b| a.partial_cmp(b).unwrap());
        let median_rtt_seconds = if sorted.is_empty() {
            0.0
        } else {
            percentile(&sorted, 50.0)
        };

        // use the same (now outlier-robust, MAD-based) jitter estimate as
        // the main check pipeline — this used to be a separate
        // variance-based calculation that diverged from check on real
        // data due to sensitivity to single outliers
        let jitter_seconds = estimate_jitter(latencies);

        let recommended_samples = if jitter_seconds > 0.0 {
            required_samples(jitter_seconds, TYPICAL_LEAK_SECONDS, 0.95)
        } else {
            0
        };

        Self {
            target,
            samples,
            median_rtt_seconds,
            jitter_seconds,
            packet_loss_ratio,
            recommended_samples,
        }
    }

    fn quality(&self) -> EnvironmentQuality {
        let jitter = classify_jitter(self.jitter_seconds);
        if self.packet_loss_ratio > 0.05 {
            return EnvironmentQuality::Poor;
        }
        match jitter {
            JitterLevel::Low => EnvironmentQuality::Good,
            JitterLevel::Medium => {
                if self.packet_loss_ratio > 0.0 {
                    EnvironmentQuality::Fair
                } else {
                    EnvironmentQuality::Good
                }
            }
            JitterLevel::High => EnvironmentQuality::Poor,
        }
    }

    pub fn render(&self) -> String {
        let jitter_level = classify_jitter(self.jitter_seconds);
        let quality = self.quality();

        let mut out = String::new();
        out.push_str(&"─".repeat(48));
        out.push_str("\nsidecheck doctor\n");
        out.push_str(&"─".repeat(48));
        out.push_str(&format!("\n\ntarget                {}\n", self.target));
        out.push_str(&format!("samples                {}\n\n", self.samples));
        out.push_str(&format!(
            "median RTT:            {:.1} ms\n",
            self.median_rtt_seconds * 1000.0
        ));
        out.push_str(&format!(
            "RTT jitter:            {:.2} ms ({})\n",
            self.jitter_seconds * 1000.0,
            jitter_level.label()
        ));
        out.push_str(&format!(
            "packet loss:           {:.1}%\n",
            self.packet_loss_ratio * 100.0
        ));
        if self.recommended_samples > 50_000_000 {
            out.push_str("recommended samples:   effectively unbounded — a ~1μs leak is not\n                       reliably measurable over this path\n");
        } else {
            out.push_str(&format!(
                "recommended samples:   ~{} (to reliably detect a ~1μs leak, the\n                       rough scale of a real == vs constant-time bug)\n",
                self.recommended_samples
            ));
        }
        out.push_str(&format!("environment quality:   {}\n", quality.label()));

        out.push_str(&"─".repeat(48));
        out.push('\n');
        match quality {
            EnvironmentQuality::Good => {
                out.push_str("this path looks suitable for timing measurement. proceed with `sidecheck check`.\n");
            }
            EnvironmentQuality::Fair => {
                out.push_str(
                    "usable, but expect to need a larger sample size for small leaks. \
                     `sidecheck check` will size the run automatically based on what it finds.\n",
                );
            }
            EnvironmentQuality::Poor => {
                out.push_str(
                    "this path is too noisy/lossy for reliable timing measurement of a \
                     realistic-sized leak. this is a property of the network path, not proof \
                     the endpoint is safe. test from a lower-latency vantage point (same \
                     LAN/datacenter as the target, or from the server itself) if you can.\n",
                );
            }
        }

        out
    }
}
