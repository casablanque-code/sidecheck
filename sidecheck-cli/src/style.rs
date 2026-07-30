//! Small helpers for coloring terminal output.
//!
//! `console::Style` no-ops automatically when stdout/stderr isn't a tty
//! (piped into a file, `sidecheck check ... | tee log.txt`, CI logs) or
//! when `NO_COLOR` is set, so callers never need to check for that
//! themselves — plain-text output "just happens" in those cases.

use console::Style;

pub fn bold() -> Style {
    Style::new().bold()
}

pub fn dim() -> Style {
    Style::new().dim()
}

pub fn label() -> Style {
    Style::new().dim()
}

pub fn value() -> Style {
    Style::new().cyan()
}

pub fn ok_style() -> Style {
    Style::new().green().bold()
}

pub fn warn_style() -> Style {
    Style::new().yellow().bold()
}

pub fn err_style() -> Style {
    Style::new().red().bold()
}

/// `✓` in green — a clean/passing result.
pub fn ok_mark() -> String {
    ok_style().apply_to("✓").to_string()
}

/// `⚠` in yellow — a leak/regression/ambiguous result that needs
/// attention but isn't necessarily a hard failure of the tool itself.
pub fn warn_mark() -> String {
    warn_style().apply_to("⚠").to_string()
}

/// `✗` in red — a hard failure (e.g. a confirmed regression).
pub fn err_mark() -> String {
    err_style().apply_to("✗").to_string()
}

/// A dim horizontal rule, `width` characters wide.
pub fn rule(width: usize) -> String {
    dim().apply_to("─".repeat(width)).to_string()
}

/// A bold section title.
pub fn title(text: &str) -> String {
    bold().apply_to(text).to_string()
}

/// A right-padded, dimmed field label for a `label   value` line, e.g.
/// `field("target", 16)` -> dimmed "target" padded to 16 columns.
pub fn field(text: &str, pad_to: usize) -> String {
    label().apply_to(format!("{text:<pad_to$}")).to_string()
}

/// Prints a `warning: ...` line to stderr in yellow. For situations the
/// user should know about but that don't stop the run.
pub fn warning(msg: &str) {
    eprintln!("{} {msg}", warn_style().apply_to("warning:"));
}

/// Prints a styled `error: ...` line (and an optional `hint: ...` line)
/// to stderr, then exits with status 1.
///
/// Use this for operator-facing setup/runtime problems where sidecheck
/// itself is working correctly but can't proceed (target unreachable,
/// signal too small to measure, etc.) — situations where we already know
/// exactly what's wrong and what to do about it. Internal errors that
/// haven't been diagnosed into a specific hint should keep going through
/// `anyhow::bail!`/`?` instead, so they surface with full context.
pub fn fatal(msg: &str, hint: Option<&str>) -> ! {
    eprintln!("{} {msg}", err_style().apply_to("error:"));
    if let Some(hint) = hint {
        eprintln!("{} {hint}", Style::new().cyan().bold().apply_to("hint:"));
    }
    std::process::exit(1);
}
