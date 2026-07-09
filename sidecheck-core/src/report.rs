//! Перевод статистики в понятный человеку вердикт.
//! Никаких сырых t-значений наружу — только то, что нужно для решения.

use crate::stats::BoxTestResult;

pub struct DetectionReport {
    pub target: String,
    pub field: String,
    pub samples_per_class: usize,
    pub result: BoxTestResult,
    pub jitter_seconds: f64,
    pub failures: usize,
}

impl DetectionReport {
    pub fn render(&self) -> String {
        let leak_us = self.result.estimated_leak * 1_000_000.0;
        let jitter_ms = self.jitter_seconds * 1000.0;
        let significant = self.result.is_significant();

        let mut out = String::new();
        out.push_str(&"─".repeat(48));
        out.push_str("\nsidecheck timing report\n");
        out.push_str(&"─".repeat(48));
        out.push_str(&format!("\n\ntarget          {}\n", self.target));
        out.push_str(&format!("field            {}\n", self.field));
        out.push_str(&format!("samples/class    {}\n", self.samples_per_class));
        out.push_str(&format!("network jitter   {:.2} ms\n", jitter_ms));
        if self.failures > 0 {
            out.push_str(&format!("failed requests  {} (excluded from analysis)\n", self.failures));
        }
        out.push('\n');

        if significant {
            out.push_str(&format!("⚠ timing leak detected\n"));
            out.push_str(&format!("  estimated leak   {:.1} μs\n", leak_us.abs()));
            out.push_str(&format!(
                "  confidence       {:.1}%\n",
                self.result.confidence * 100.0
            ));
            out.push_str("\n  this endpoint responds measurably differently depending on\n");
            out.push_str("  input correctness. an attacker can exploit this to recover\n");
            out.push_str("  secrets character-by-character instead of brute-forcing them.\n\n");
            out.push_str("  fix: use a constant-time comparison instead of == on secret\n");
            out.push_str("  bytes (e.g. the `subtle` crate in Rust, `crypto/subtle` in Go,\n");
            out.push_str("  `hmac.compare_digest` in Python).\n");
        } else {
            out.push_str("✓ no statistically significant timing difference detected\n");
            out.push_str(&format!(
                "  (95% CI of the difference: [{:.1}, {:.1}] μs, includes zero)\n",
                self.result.ci_low * 1_000_000.0,
                self.result.ci_high * 1_000_000.0
            ));
        }
        out
    }
}
