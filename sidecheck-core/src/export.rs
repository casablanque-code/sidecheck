//! Экспорт результатов — CSV с сырыми измерениями (для независимой
//! перепроверки статистики кем угодно) и JSON-отчёт (для CI/автоматизации).

use crate::report::DetectionReport;
use crate::sampler::RawSamples;
use crate::stats::BOOTSTRAP_ITERATIONS;
use anyhow::{Context, Result};
use serde::Serialize;
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

/// Машиночитаемый отчёт для CI/автоматизации/приложения к bug bounty.
/// Всегда несёт версию sidecheck и seed — через год алгоритм статистики
/// может измениться, и без версии старый отчёт станет непонятно, чему верить.
#[derive(Serialize)]
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
