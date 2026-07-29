//! Result export — CSV with raw measurements (for anyone to independently
//! re-check the statistics) and a JSON report (for CI/automation).

use crate::report::DetectionReport;
use crate::sampler::RawSamples;
use crate::stats::BOOTSTRAP_ITERATIONS;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

pub fn write_csv(path: &Path, raw: &RawSamples) -> Result<()> {
    let mut file = std::fs::File::create(path)
        .with_context(|| format!("failed to create {}", path.display()))?;

    writeln!(file, "class,elapsed_seconds")?;
    for v in &raw.class_a {
        writeln!(file, "a,{v:.9}")?;
    }
    for v in &raw.class_b {
        writeln!(file, "b,{v:.9}")?;
    }

    Ok(())
}

/// Machine-readable report for CI/automation/bug bounty attachments.
/// Always carries the sidecheck version and seed — a year from now the
/// statistics algorithm may have changed, and without a version an old
/// report becomes unclear about what to trust.
#[derive(Serialize, Deserialize)]
pub struct JsonReport {
    pub target: String,
    pub injection_point: String,
    pub samples_per_class: usize,
    pub jitter_ms: f64,
    pub estimated_leak_us: f64,
    pub significant: bool,
    pub bootstrap_confidence: f64,
    pub bootstrap_iterations: usize,
    pub ci_low_us: f64,
    pub ci_high_us: f64,
    pub failed_requests: usize,
    pub seed: u64,
    pub timestamp_unix: u64,
    pub sidecheck_version: String,
}

impl JsonReport {
    pub fn from_detection(report: &DetectionReport) -> Self {
        Self {
            target: report.target.clone(),
            injection_point: report.field.clone(),
            samples_per_class: report.samples_per_class,
            jitter_ms: report.jitter_seconds * 1000.0,
            estimated_leak_us: report.result.estimated_leak * 1_000_000.0,
            significant: report.result.is_significant(),
            bootstrap_confidence: report.result.confidence,
            bootstrap_iterations: BOOTSTRAP_ITERATIONS,
            ci_low_us: report.result.ci_low * 1_000_000.0,
            ci_high_us: report.result.ci_high * 1_000_000.0,
            failed_requests: report.failures,
            seed: report.seed,
            timestamp_unix: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
            sidecheck_version: report.sidecheck_version.clone(),
        }
    }
}

pub fn write_json(path: &Path, report: &DetectionReport) -> Result<()> {
    let json_report = JsonReport::from_detection(report);
    let text =
        serde_json::to_string_pretty(&json_report).context("failed to serialize report to JSON")?;
    std::fs::write(path, text).with_context(|| format!("failed to write {}", path.display()))?;
    Ok(())
}

/// Reads back a report previously written by `write_json` — used by
/// `sidecheck compare` to load both sides of a baseline/current
/// comparison. Deliberately lenient about `sidecheck_version`: an older
/// report from a previous release should still load, since comparing
/// across versions (the whole point of a CI baseline) is the normal
/// case, not an error condition.
pub fn read_json(path: &Path) -> Result<JsonReport> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read {}", path.display()))?;
    serde_json::from_str(&text)
        .with_context(|| format!("{} is not a valid sidecheck JSON report", path.display()))
}
