//! Colored terminal renderings of the report types from `sidecheck-core`.
//!
//! These mirror `DetectionReport::render()` / `DoctorReport::render()`
//! content-for-content, just with color and layout applied. Kept in the
//! CLI crate rather than core: core is a library other things (the GitHub
//! Action, someone's own tooling) may consume without wanting ANSI codes
//! baked into the string they get back. Core's own `render()` stays as
//! the plain-text fallback (e.g. useful if output isn't a tty and a
//! caller wants guaranteed-plain text without relying on `console`'s
//! auto-detection).

use crate::style;
use sidecheck_core::doctor::DoctorReport;
use sidecheck_core::export::JsonReport;
use sidecheck_core::report::DetectionReport;

const WIDTH: usize = 48;

/// Auto-picks ns/μs/ms/s so we don't print "16264.9 μs" where "16.3 ms"
/// reads easier. Kept here (rather than importing a private fn from
/// core) since it's a display concern, not a statistics one.
pub fn format_duration(seconds: f64) -> String {
    let abs = seconds.abs();
    if abs >= 1.0 {
        format!("{seconds:.3} s")
    } else if abs >= 0.001 {
        format!("{:.2} ms", seconds * 1_000.0)
    } else if abs >= 0.000_001 {
        format!("{:.1} μs", seconds * 1_000_000.0)
    } else {
        format!("{:.0} ns", seconds * 1_000_000_000.0)
    }
}

/// Greedy word-wrap to `width` columns — used for the free-text
/// explanation/fix lines inside a panel, which are too long to fit on
/// one bordered line.
fn wrap(text: &str, width: usize) -> Vec<String> {
    let mut lines = Vec::new();
    let mut current = String::new();
    for word in text.split_whitespace() {
        let candidate_len = if current.is_empty() {
            word.len()
        } else {
            current.len() + 1 + word.len()
        };
        if candidate_len > width && !current.is_empty() {
            lines.push(std::mem::take(&mut current));
        }
        if !current.is_empty() {
            current.push(' ');
        }
        current.push_str(word);
    }
    if !current.is_empty() {
        lines.push(current);
    }
    lines
}

pub fn detection(report: &DetectionReport) -> String {
    let jitter = format_duration(report.jitter_seconds);
    let significant = report.result.is_significant();
    let mut out = String::new();
    let p = |s: &str| style::panel::line(s);

    out.push_str(&style::panel::top("sidecheck timing report"));
    out.push('\n');
    out.push_str(&p(&format!(
        "{}{}",
        style::field("target", 17),
        style::value().apply_to(&report.target)
    )));
    out.push('\n');
    out.push_str(&p(&format!(
        "{}{}",
        style::field("field", 17),
        style::value().apply_to(&report.field)
    )));
    out.push('\n');
    out.push_str(&p(&format!(
        "{}{}",
        style::field("samples/class", 17),
        report.samples_per_class
    )));
    out.push('\n');
    out.push_str(&p(&format!("{}{}", style::field("network jitter", 17), jitter)));
    out.push('\n');
    if report.failures > 0 {
        out.push_str(&p(&format!(
            "{}{} (excluded from analysis)",
            style::field("failed requests", 17),
            style::warn_style().apply_to(report.failures)
        )));
        out.push('\n');
    }

    out.push_str(&style::panel::divider());
    out.push('\n');

    if significant {
        out.push_str(&p(&format!(
            "{} {}",
            style::warn_mark(),
            style::warn_style().apply_to("LEAK DETECTED")
        )));
        out.push('\n');
        out.push_str(&style::panel::blank());
        out.push('\n');
        out.push_str(&p(&format!(
            "{}{}",
            style::field("estimated leak", 18),
            style::bold().apply_to(format_duration(report.result.estimated_leak.abs()))
        )));
        out.push('\n');
        // "confidence" alone reads as "probability the server is
        // vulnerable" — this is the bootstrap CI of the measured
        // difference, not a probability of vulnerability or a p-value;
        // the fuller wording is in the wrapped paragraph below instead
        // of crammed onto this line.
        out.push_str(&p(&format!(
            "{}{:.1}%",
            style::field("bootstrap confidence", 18),
            report.result.confidence * 100.0
        )));
        out.push('\n');
        out.push_str(&style::panel::blank());
        out.push('\n');
        for l in wrap(
            "this endpoint responds measurably differently depending on input \
             correctness. an attacker can exploit this to recover secrets \
             character-by-character instead of brute-forcing them.",
            style::panel::CONTENT_WIDTH,
        ) {
            out.push_str(&p(&style::dim().apply_to(&l).to_string()));
            out.push('\n');
        }
        out.push_str(&style::panel::blank());
        out.push('\n');
        for l in wrap(
            "fix: use a constant-time comparison instead of == on secret bytes \
             (e.g. the subtle crate in Rust, crypto/subtle in Go, \
             hmac.compare_digest in Python).",
            style::panel::CONTENT_WIDTH,
        ) {
            out.push_str(&p(&l));
            out.push('\n');
        }
    } else {
        out.push_str(&p(&format!(
            "{} {}",
            style::ok_mark(),
            style::ok_style().apply_to("NO LEAK")
        )));
        out.push('\n');
        out.push_str(&p("no statistically significant timing difference detected"));
        out.push('\n');
        out.push_str(&style::panel::blank());
        out.push('\n');
        for l in wrap(
            &format!(
                "bootstrap {:.0}% CI of the difference: [{}, {}] — includes zero",
                report.result.confidence * 100.0,
                format_duration(report.result.ci_low),
                format_duration(report.result.ci_high)
            ),
            style::panel::CONTENT_WIDTH,
        ) {
            out.push_str(&p(&style::dim().apply_to(&l).to_string()));
            out.push('\n');
        }
    }

    out.push_str(&style::panel::bottom());
    out.push('\n');
    out.push_str(
        &style::dim()
            .apply_to(
                "sidecheck cannot prove the absence of a timing leak — only detect a \
                 statistically significant one under the tested conditions. A clean \
                 result here is not a safety guarantee.",
            )
            .to_string(),
    );
    out.push('\n');
    out.push_str(
        &style::dim()
            .apply_to(format!(
                "generated by sidecheck {} · seed {} (rerun with --seed {} to reproduce request order)",
                report.sidecheck_version, report.seed, report.seed
            ))
            .to_string(),
    );
    out.push('\n');

    out
}

pub fn doctor(report: &DoctorReport) -> String {
    // DoctorReport's quality/jitter classification is private to core,
    // so re-derive the same thresholds here rather than exposing an
    // internal enum as public API just for CLI coloring. Kept in sync
    // with `doctor::classify_jitter`/`DoctorReport::quality`.
    let jitter_level = if report.jitter_seconds < 0.001 {
        "low"
    } else if report.jitter_seconds < 0.010 {
        "medium"
    } else {
        "high"
    };
    enum Quality {
        Good,
        Fair,
        Poor,
    }
    let quality = if report.packet_loss_ratio > 0.05 {
        Quality::Poor
    } else {
        match jitter_level {
            "low" => Quality::Good,
            "medium" if report.packet_loss_ratio > 0.0 => Quality::Fair,
            "medium" => Quality::Good,
            _ => Quality::Poor,
        }
    };

    let recommended = if report.recommended_samples > 50_000_000 {
        style::warn_style()
            .apply_to("effectively unbounded — not reliably measurable")
            .to_string()
    } else {
        format!("~{}", report.recommended_samples)
    };
    let quality_badge = match quality {
        Quality::Good => style::badge("GOOD", style::Badge::Ok),
        Quality::Fair => style::badge("FAIR", style::Badge::Warn),
        Quality::Poor => style::badge("POOR", style::Badge::Err),
    };

    // Column 1 (labels) is a fixed width; column 2 sizes to the widest
    // value actually present so the table doesn't waste space on a
    // target URL that's shorter than the recommended-samples sentence,
    // or get clipped by one that's longer.
    let col1 = 20;
    let rows: Vec<(String, String)> = vec![
        ("target".into(), style::value().apply_to(&report.target).to_string()),
        ("samples".into(), report.samples.to_string()),
        (
            "median RTT".into(),
            format!("{:.1} ms", report.median_rtt_seconds * 1000.0),
        ),
        (
            "RTT jitter".into(),
            format!("{:.2} ms ({jitter_level})", report.jitter_seconds * 1000.0),
        ),
        (
            "packet loss".into(),
            format!("{:.1}%", report.packet_loss_ratio * 100.0),
        ),
        ("recommended samples".into(), recommended),
        ("environment quality".into(), quality_badge),
    ];
    let col2 = rows
        .iter()
        .map(|(_, v)| style::visible_width(v))
        .max()
        .unwrap_or(10)
        .max(10);

    let mut out = String::new();
    out.push_str(&style::table::top(col1, col2));
    out.push('\n');
    for (label, value) in &rows {
        out.push_str(&style::table::row(label, col1, value, col2));
        out.push('\n');
    }
    out.push_str(&style::table::bottom(col1, col2));
    out.push('\n');

    match quality {
        Quality::Good => out.push_str(&format!(
            "{} this path looks suitable for timing measurement. proceed with `sidecheck check`.\n",
            style::ok_mark()
        )),
        Quality::Fair => out.push_str(
            "usable, but expect to need a larger sample size for small leaks. \
             `sidecheck check` will size the run automatically based on what it finds.\n",
        ),
        Quality::Poor => out.push_str(&format!(
            "{} this path is too noisy/lossy for reliable timing measurement of a \
             realistic-sized leak. this is a property of the network path, not proof \
             the endpoint is safe. test from a lower-latency vantage point (same \
             LAN/datacenter as the target, or from the server itself) if you can.\n",
            style::warn_mark()
        )),
    }

    out
}

pub fn compare(base: &JsonReport, cur: &JsonReport) -> String {
    let mut out = String::new();
    out.push_str(&style::rule(WIDTH));
    out.push('\n');
    out.push_str(&style::title("sidecheck compare"));
    out.push_str("\n\n");

    out.push_str(&format!(
        "{}{}\n",
        style::field("target", 18),
        style::value().apply_to(&cur.target)
    ));
    out.push_str(&format!(
        "{}{}\n",
        style::field("field", 18),
        style::value().apply_to(&cur.injection_point)
    ));
    out.push_str(&format!(
        "{}{} (sidecheck {})\n",
        style::field("baseline", 18),
        if base.significant {
            "leak detected"
        } else {
            "clean"
        },
        base.sidecheck_version
    ));
    out.push_str(&format!(
        "{}{} (sidecheck {})\n",
        style::field("current", 18),
        if cur.significant {
            "leak detected"
        } else {
            "clean"
        },
        cur.sidecheck_version
    ));

    let is_regression = !base.significant && cur.significant;

    out.push_str(&style::rule(WIDTH));
    out.push('\n');
    if is_regression {
        out.push_str(&format!(
            "{} regression: no leak in the baseline, but a significant one now\n  {}{:.1} μs (95% CI [{:.1}, {:.1}] μs)\n\n{}\n",
            style::err_mark(),
            style::field("estimated leak", 16),
            cur.estimated_leak_us,
            cur.ci_low_us,
            cur.ci_high_us,
            style::dim().apply_to(
                "this change appears to have introduced a timing leak that wasn't\nthere before."
            )
        ));
        out.push_str(&style::rule(WIDTH));
        out.push('\n');
    } else if base.significant && !cur.significant {
        out.push_str(&format!(
            "{} improved: the baseline's leak is no longer significant.\n  {}\n",
            style::ok_mark(),
            style::dim().apply_to(
                "(still verify this is a real fix, not just a noisier run —\n  see docs/limitations.md on what a clean result does and doesn't mean)"
            )
        ));
    } else if base.significant && cur.significant {
        out.push_str(&format!(
            "{} leak present in both baseline and current — not flagged as a NEW\n  regression by this comparison, but it's still an existing problem.\n  {}{:.1} μs\n  {}{:.1} μs\n",
            style::warn_mark(),
            style::field("baseline leak", 16),
            base.estimated_leak_us,
            style::field("current leak", 16),
            cur.estimated_leak_us
        ));
    } else {
        out.push_str(&format!(
            "{} no leak in baseline or current.\n",
            style::ok_mark()
        ));
    }
    out.push_str(&style::rule(WIDTH));
    out.push('\n');

    out
}

/// `true` if `compare()`'s output represents a hard regression — the CLI
/// uses this to decide the process exit code without re-deriving the
/// condition itself.
pub fn compare_is_regression(base: &JsonReport, cur: &JsonReport) -> bool {
    !base.significant && cur.significant
}
