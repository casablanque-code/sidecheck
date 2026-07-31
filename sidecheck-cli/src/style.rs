//! Small helpers for coloring terminal output.
//!
//! `console::Style` no-ops automatically when stdout/stderr isn't a tty
//! (piped into a file, `sidecheck check ... | tee log.txt`, CI logs) or
//! when `NO_COLOR` is set, so callers never need to check for that
//! themselves — plain-text output "just happens" in those cases.

use console::Style;

/// Visible width of `s` — same as `.chars().count()` but skipping ANSI
/// escape sequences (`\x1b[...m`), so padding a line that contains
/// colored text still lines up. Assumes 1 display column per remaining
/// char, which is fine for the ASCII/Latin-1 + a handful of symbols
/// (μ, ✓, ⚠, ✗, ─, │, ╭...) that ever appear in this CLI's output.
pub fn visible_width(s: &str) -> usize {
    let mut width = 0;
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' {
            for c2 in chars.by_ref() {
                if c2 == 'm' {
                    break;
                }
            }
        } else {
            width += 1;
        }
    }
    width
}

/// A colored status chip with a filled background, e.g. ` GOOD `,
/// ` LEAK DETECTED `. `style` picks the color (ok_style/warn_style/err_style);
/// only the `.fg()`/bold-ness matters, the background is always set to
/// match so the chip reads as a solid block rather than colored text.
pub fn badge(text: &str, kind: Badge) -> String {
    let padded = format!(" {text} ");
    let style = match kind {
        Badge::Ok => Style::new().black().on_color256(84).bold(),
        Badge::Warn => Style::new().black().on_color256(220).bold(),
        Badge::Err => Style::new().white().on_color256(160).bold(),
    };
    style.apply_to(padded).to_string()
}

pub enum Badge {
    Ok,
    Warn,
    Err,
}

/// Single-column panel (a "Panel" in Spectre.Console terms): title baked
/// into the top border, content lines padded to line up regardless of
/// embedded ANSI color codes.
pub mod panel {
    use super::visible_width;
    use console::Style;

    /// Total visible width of every line this panel prints, corners
    /// included. Content lines get 1 space of padding on each side, so
    /// `panel::line` wraps text to `WIDTH - 4` columns.
    pub const WIDTH: usize = 56;
    pub const CONTENT_WIDTH: usize = WIDTH - 4;

    fn dim() -> Style {
        Style::new().dim()
    }

    pub fn top(title: &str) -> String {
        let dashes_total = WIDTH.saturating_sub(2);
        // "─" + " " + title + " " precedes the fill of dashes before "╮"
        let head_len = 1 + 1 + title.chars().count() + 1;
        let after = dashes_total.saturating_sub(head_len);
        format!(
            "{}{}{}{}",
            dim().apply_to("╭─ "),
            super::bold().apply_to(title),
            dim().apply_to(format!(" {}", "─".repeat(after))),
            dim().apply_to("╮"),
        )
    }

    pub fn bottom() -> String {
        dim()
            .apply_to(format!("╰{}╯", "─".repeat(WIDTH.saturating_sub(2))))
            .to_string()
    }

    pub fn divider() -> String {
        dim()
            .apply_to(format!("├{}┤", "─".repeat(WIDTH.saturating_sub(2))))
            .to_string()
    }

    /// A blank line inside the panel (still bordered).
    pub fn blank() -> String {
        line("")
    }

    /// A content line — `content` may contain ANSI styling; padding is
    /// computed from its visible width, not its byte length. Lines
    /// longer than `CONTENT_WIDTH` are not wrapped (callers keep their
    /// text short enough to fit; this is a fixed-width terminal panel,
    /// not a reflowing one).
    pub fn line(content: &str) -> String {
        let pad = CONTENT_WIDTH.saturating_sub(visible_width(content));
        format!(
            "{}{}{}{}",
            dim().apply_to("│ "),
            content,
            " ".repeat(pad),
            dim().apply_to(" │"),
        )
    }
}

/// Two-column table (used by `sidecheck doctor`): fixed label column,
/// value column sized to fit the widest value.
pub mod table {
    use super::visible_width;
    use console::Style;

    fn dim() -> Style {
        Style::new().dim()
    }

    pub fn top(col1: usize, col2: usize) -> String {
        dim()
            .apply_to(format!(
                "╭{}┬{}╮",
                "─".repeat(col1 + 2),
                "─".repeat(col2 + 2)
            ))
            .to_string()
    }

    pub fn bottom(col1: usize, col2: usize) -> String {
        dim()
            .apply_to(format!(
                "╰{}┴{}╯",
                "─".repeat(col1 + 2),
                "─".repeat(col2 + 2)
            ))
            .to_string()
    }

    /// `col1_text`/`col2_text` may contain ANSI styling; both columns
    /// pad based on visible width.
    pub fn row(col1_text: &str, col1: usize, col2_text: &str, col2: usize) -> String {
        let pad1 = col1.saturating_sub(visible_width(col1_text));
        let pad2 = col2.saturating_sub(visible_width(col2_text));
        format!(
            "{}{}{}{}{}{}{}",
            dim().apply_to("│ "),
            col1_text,
            " ".repeat(pad1),
            dim().apply_to(" │ "),
            col2_text,
            " ".repeat(pad2),
            dim().apply_to(" │"),
        )
    }
}

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
