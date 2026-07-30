use anyhow::{Context, Result};
use clap::{ArgGroup, Parser, Subcommand};
use indicatif::{ProgressBar, ProgressStyle};
use rand::{rngs::StdRng, Rng, SeedableRng};
use sidecheck_core::{
    doctor::DoctorReport,
    export,
    report::DetectionReport,
    sampler::{self, InjectionPoint},
    stats,
};
use std::io::BufRead;
use std::path::PathBuf;

mod render;
mod style;

#[derive(Parser)]
#[command(
    name = "sidecheck",
    version,
    about = "Timing side-channel auditor for your own services"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
// Commands is parsed and matched once at startup, not stored in
// collections and not on the hot path — the size difference between
// variants (Check is notably bigger than Doctor) has no practical impact
// here. Boxing individual fields just to satisfy this lint would add
// indirection with no real benefit.
#[allow(clippy::large_enum_variant)]
enum Commands {
    /// Check an HTTP endpoint for a timing side-channel
    #[command(group(
        ArgGroup::new("secret_mode")
            .required(true)
            .args(["secret", "secret_env", "secret_stdin", "value_b"])
    ))]
    #[command(group(
        ArgGroup::new("injection")
            .required(true)
            .args(["header", "query", "json_field"])
    ))]
    Check {
        /// Endpoint URL, e.g. https://myapp.local/login
        url: String,

        /// Inject the value into this HTTP header
        #[arg(long, value_name = "NAME")]
        header: Option<String>,
        /// Inject the value into this query parameter (GET ?name=value)
        #[arg(long, value_name = "NAME")]
        query: Option<String>,
        /// Inject the value into this field of the POST JSON body
        #[arg(long, value_name = "NAME")]
        json_field: Option<String>,
        /// Template for the rest of the JSON body fields (needed only if
        /// the endpoint requires fields other than --json-field to reach
        /// the secret comparison), e.g.:
        /// --json-body '{"username": "admin"}'
        /// No need to include the --json-field field in the template — it
        /// gets added/overwritten automatically on every request.
        /// Requires --json-field (checked manually — clap's `requires`
        /// doesn't fire reliably combined with an ArgGroup here).
        #[arg(long, value_name = "JSON")]
        json_body: Option<String>,

        /// Simple mode: your real secret directly as an argument. Visible
        /// in `ps aux` and shell history — use --secret-env or
        /// --secret-stdin for sensitive secrets.
        #[arg(long)]
        secret: Option<String>,
        /// Read the secret from this environment variable (doesn't show up
        /// in `ps aux`/shell history) — the preferred way
        #[arg(long, value_name = "VAR")]
        secret_env: Option<String>,
        /// Read the secret from stdin (a single line, no trailing
        /// newline) — handy for piping from a password manager:
        /// `pass show x | sidecheck ... --secret-stdin`
        #[arg(long, default_value_t = false)]
        secret_stdin: bool,

        /// Advanced mode: a deliberately wrong value (class A)
        #[arg(long, requires = "value_b")]
        value_a: Option<String>,
        /// Advanced mode: a value with a correct prefix / fully correct
        /// (class B)
        #[arg(long)]
        value_b: Option<String>,

        /// Number of measurements per class. If not given, it's picked
        /// automatically from the pilot run.
        #[arg(long)]
        samples: Option<usize>,
        /// Ceiling for the automatically chosen sample count
        #[arg(long, default_value_t = 200_000)]
        max_samples: usize,
        /// Pilot run size for estimating network jitter
        #[arg(long, default_value_t = 300)]
        pilot_samples: usize,
        /// Block size for randomized interleaving of classes
        #[arg(long, default_value_t = 20)]
        block_size: usize,
        /// Confidence level for the output (0.0-1.0)
        #[arg(long, default_value_t = 0.95)]
        confidence: f64,
        /// Low percentile for the box test (per the Crosby-Wallach
        /// methodology)
        #[arg(long, default_value_t = 10.0)]
        percentile: f64,
        /// Accept self-signed/invalid TLS certificates (for homelab use)
        #[arg(long, default_value_t = false)]
        insecure: bool,
        /// Static header sent unchanged on every request, as NAME=VALUE
        /// (repeatable). For whatever the endpoint needs to reach the
        /// code path under test that isn't the value being measured —
        /// a CSRF token, a session cookie, a Bearer token for a
        /// different auth layer than the one under test:
        /// --extra-header 'Cookie=session=abc123'
        /// --extra-header 'X-CSRF-Token=xyz'
        #[arg(long = "extra-header", value_name = "NAME=VALUE")]
        extra_headers: Vec<String>,
        /// Save the raw measurements to CSV (class,elapsed_seconds) for
        /// independently re-checking the statistics
        #[arg(long, value_name = "PATH")]
        output_csv: Option<PathBuf>,
        /// Save a machine-readable JSON report (for CI/automation)
        #[arg(long, value_name = "PATH")]
        report: Option<PathBuf>,
        /// Seed for the random number generator — fixes the request
        /// interleaving order so the run can be reproduced exactly.
        /// If not given, one is generated randomly and printed in the
        /// report.
        #[arg(long)]
        seed: Option<u64>,
        /// Proceed anyway even if the jitter estimate gathered at
        /// --max-samples clearly won't have enough power for a
        /// significant result (by default sidecheck stops in this case,
        /// so it doesn't burn hours on a run that will be inconclusive
        /// regardless)
        #[arg(long, default_value_t = false)]
        force: bool,
        /// Run the whole experiment (pilot + main measurement) N times in
        /// a row and show how stable the leak estimate is across runs —
        /// if the result "wanders" from run to run, it can't be trusted
        /// the same way a stable one can.
        #[arg(long, default_value_t = 1)]
        repeat: usize,
    },

    /// Pre-flight check of the network path to the target, before
    /// spending time on a full check. Answers "is it even worth trying
    /// to measure timing here", not "is there a leak".
    Doctor {
        /// Target URL, e.g. https://myapp.local/login
        url: String,
        /// Number of measurements for estimating RTT/jitter/loss
        #[arg(long, default_value_t = 300)]
        samples: usize,
        /// Accept self-signed/invalid TLS certificates
        #[arg(long, default_value_t = false)]
        insecure: bool,
        /// Static header sent unchanged on every probe request, as
        /// NAME=VALUE (repeatable) — same as `check`'s flag, useful when
        /// the endpoint needs a CSRF token/session cookie to give a
        /// realistic RTT reading at all.
        #[arg(long = "extra-header", value_name = "NAME=VALUE")]
        extra_headers: Vec<String>,
    },

    /// Compare a baseline report against a current one and flag whether a
    /// new timing leak was introduced — for CI: fail the build only on a
    /// regression, not on a leak that was already there before this
    /// change (that's a separate, pre-existing problem to track on its
    /// own, not something this specific change should be blamed for).
    Compare {
        /// JSON report from a previous run (--report), e.g. from the base
        /// branch
        baseline: PathBuf,
        /// JSON report from the current run to compare against it
        current: PathBuf,
    },
}

/// Minimum samples per class — below this, the low percentile is
/// statistically shaky even if the jitter-based formula says a smaller
/// number would suffice to detect an effect of that size.
const MIN_SAMPLES: usize = 200;

/// Parses repeated --extra-header NAME=VALUE arguments. Splits on the
/// first '=' only, so a value that itself contains '=' (a cookie pair,
/// a base64 token with padding) is preserved intact.
fn parse_extra_headers(raw: &[String]) -> Result<Vec<(String, String)>> {
    raw.iter()
        .map(|entry| {
            entry
                .split_once('=')
                .map(|(name, value)| (name.to_string(), value.to_string()))
                .with_context(|| {
                    format!(
                        "--extra-header '{entry}' is not in NAME=VALUE form \
                         (e.g. --extra-header 'X-CSRF-Token=xyz')"
                    )
                })
        })
        .collect()
}

fn format_wall_time(seconds: f64) -> String {
    if seconds < 60.0 {
        format!("{seconds:.0}s")
    } else if seconds < 3600.0 {
        format!("{:.0}m", seconds / 60.0)
    } else {
        format!("{:.1}h", seconds / 3600.0)
    }
}

fn read_secret(
    secret: Option<String>,
    secret_env: Option<String>,
    secret_stdin: bool,
) -> Result<Option<String>> {
    if let Some(s) = secret {
        style::warning(
            "secret passed via --secret is visible in `ps aux` and shell history. \
             Prefer --secret-env or --secret-stdin for anything sensitive.",
        );
        return Ok(Some(s));
    }
    if let Some(var) = secret_env {
        let value = std::env::var(&var)
            .with_context(|| format!("environment variable {var} is not set"))?;
        return Ok(Some(value));
    }
    if secret_stdin {
        let stdin = std::io::stdin();
        let mut line = String::new();
        stdin
            .lock()
            .read_line(&mut line)
            .context("failed to read secret from stdin")?;
        return Ok(Some(line.trim_end_matches(['\n', '\r']).to_string()));
    }
    Ok(None)
}

/// Result of one full check run (pilot + main measurement).
struct RunResult {
    result: stats::BoxTestResult,
    jitter_seconds: f64,
    samples_per_class: usize,
    raw: sampler::RawSamples,
}

#[allow(clippy::too_many_arguments)]
fn run_one_check(
    target: &sampler::HttpTarget,
    val_a: &str,
    val_b: &str,
    pilot_samples: usize,
    block_size: usize,
    max_samples: usize,
    explicit_samples: Option<usize>,
    percentile: f64,
    confidence: f64,
    force: bool,
    show_progress: bool,
    rng: &mut StdRng,
) -> Result<RunResult> {
    eprintln!("running pilot batch ({pilot_samples} samples/class) to estimate network jitter...");
    let pilot = sampler::run_interleaved(
        target,
        val_a,
        val_b,
        pilot_samples,
        block_size,
        rng,
        |_, _| {},
    )?;
    let mut combined_pilot = pilot.class_a.clone();
    combined_pilot.extend(&pilot.class_b);
    let jitter = stats::estimate_jitter(&combined_pilot);

    let pilot_result = stats::box_test(&pilot.class_a, &pilot.class_b, percentile, confidence);
    let pilot_leak = pilot_result.estimated_leak.abs();

    // Compute the final sample size in one pass and print one coherent
    // message about how we got there — instead of announcing one plan
    // and then immediately reversing it.
    let effective_samples = match explicit_samples {
        Some(n) => {
            eprintln!("using explicit --samples={n}");
            n.max(MIN_SAMPLES)
        }
        None if pilot_leak <= 0.0 => {
            let default_n = MIN_SAMPLES.max(5_000);
            eprintln!(
                "pilot found no measurable difference; using default sample size ({default_n})"
            );
            default_n
        }
        None => {
            let needed = stats::required_samples(jitter, pilot_leak, confidence);
            if needed as usize > max_samples {
                let mean_request_time =
                    combined_pilot.iter().sum::<f64>() / combined_pilot.len() as f64;
                let capped = max_samples.max(MIN_SAMPLES);
                let estimated_wall_seconds = mean_request_time * (capped * 2) as f64;

                style::warning(&format!(
                    "network jitter ({:.2} ms) is large relative to the \
                     estimated effect ({:.1} μs) — signal-to-noise ratio is roughly \
                     1:{:.0}. {} samples would be needed for a clean signal; \
                     --max-samples={} would still fall far short and the result would \
                     almost certainly be inconclusive.",
                    jitter * 1000.0,
                    pilot_leak * 1_000_000.0,
                    jitter / pilot_leak,
                    needed,
                    max_samples
                ));
                eprintln!(
                    "  running the capped {capped} samples/class would take roughly \
                     {} at this network's measured latency, for a result that likely \
                     won't reach significance either way.",
                    format_wall_time(estimated_wall_seconds)
                );

                if !force {
                    style::fatal(
                        "stopping before wasting that time — the leak (if real) is too \
                         small to catch over this network path.",
                        Some(
                            "test from a lower-latency vantage point (same LAN/datacenter \
                             as the target, or the server itself against 127.0.0.1); pass \
                             --force to run anyway knowing the result will likely be \
                             inconclusive; or raise --max-samples if you're willing to wait \
                             much longer.",
                        ),
                    );
                }

                eprintln!("  --force given, proceeding anyway.");
                capped
            } else if (needed as usize) < MIN_SAMPLES {
                eprintln!(
                    "pilot suggests a very large, easily detectable effect (~{:.1} μs); \
                     using the floor of {MIN_SAMPLES} samples/class for stable percentile estimates",
                    pilot_leak * 1_000_000.0
                );
                MIN_SAMPLES
            } else {
                eprintln!(
                    "pilot suggests ~{:.1} μs effect; using {} samples/class for a clean signal",
                    pilot_leak * 1_000_000.0,
                    needed
                );
                needed as usize
            }
        }
    };

    let raw = if show_progress {
        let pb = ProgressBar::new((effective_samples * 2) as u64);
        pb.set_style(ProgressStyle::with_template("{bar:40} {pos}/{len} requests").unwrap());
        let raw = sampler::run_interleaved(
            target,
            val_a,
            val_b,
            effective_samples,
            block_size,
            rng,
            |done, total| {
                pb.set_position(done as u64);
                pb.set_length(total as u64);
            },
        )?;
        pb.finish_and_clear();
        raw
    } else {
        sampler::run_interleaved(
            target,
            val_a,
            val_b,
            effective_samples,
            block_size,
            rng,
            |_, _| {},
        )?
    };

    let result = stats::box_test(&raw.class_a, &raw.class_b, percentile, confidence);
    Ok(RunResult {
        result,
        jitter_seconds: jitter,
        samples_per_class: effective_samples,
        raw,
    })
}

/// With --repeat > 1 the output (CSV/JSON) needs to be split into
/// separate files, otherwise each subsequent run overwrites the previous
/// one. Inserts "-runN" before the extension; with repeat=1 the path is
/// left untouched.
fn suffix_path(path: &std::path::Path, repeat: usize, index: usize) -> PathBuf {
    if repeat <= 1 {
        return path.to_path_buf();
    }
    let stem = path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("report");
    let ext = path.extension().and_then(|s| s.to_str());
    let file_name = match ext {
        Some(ext) => format!("{stem}-run{}.{ext}", index + 1),
        None => format!("{stem}-run{}", index + 1),
    };
    path.with_file_name(file_name)
}

/// Prints how stable the leak estimate is across independent --repeat
/// runs. The spread is just as important a signal as the estimate
/// itself: if the estimated leak "wanders" from run to run, it can't be
/// trusted the way a stable result can, even if each individual run is
/// formally significant.
fn print_stability_summary(outcomes: &[(RunResult, DetectionReport)]) {
    let leaks: Vec<f64> = outcomes
        .iter()
        .map(|(r, _)| r.result.estimated_leak)
        .collect();
    let significant_count = outcomes
        .iter()
        .filter(|(r, _)| r.result.is_significant())
        .count();

    let mean = leaks.iter().sum::<f64>() / leaks.len() as f64;
    let min = leaks.iter().cloned().fold(f64::INFINITY, f64::min);
    let max = leaks.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
    let variance = leaks.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / leaks.len() as f64;
    let std_dev = variance.sqrt();

    println!("\n{}", style::rule(48));
    println!(
        "{}",
        style::title(&format!("stability summary across {} runs", outcomes.len()))
    );
    println!("{}", style::rule(48));
    println!();
    println!("significant in {significant_count}/{} runs", outcomes.len());
    println!(
        "{}mean {} · range [{}, {}] · std dev {}",
        style::field("estimated leak", 17),
        render::format_duration(mean),
        render::format_duration(min),
        render::format_duration(max),
        render::format_duration(std_dev)
    );

    // Significance is a more reliable stability signal than the relative
    // deviation of the point estimate: when there's no real leak, the
    // mean hovers around zero, and any tiny absolute deviation gives a
    // huge std_dev/mean ratio — that's not instability, it's expected
    // behavior in the absence of an effect. So we first check agreement
    // on the "significant/not significant" verdict, and only for the
    // "all runs significant" case does it make sense to ask how stable
    // the magnitude itself is.
    if significant_count == 0 {
        println!(
            "\n{} consistently no significant difference across {} runs.",
            style::ok_mark(),
            outcomes.len()
        );
    } else if significant_count == outcomes.len() {
        if std_dev > mean.abs() * 0.5 {
            println!(
                "\n{} all runs found a significant effect, but its magnitude varies \
                 substantially between runs (std dev is more than half the mean) — the \
                 direction is consistent, but don't treat any single run's exact number \
                 as precise.",
                style::warn_mark()
            );
        } else {
            println!(
                "\n{} consistently significant with a stable magnitude across runs.",
                style::ok_mark()
            );
        }
    } else {
        println!(
            "\n{} significance is inconsistent across runs ({significant_count}/{} found a \
             signal) — likely sitting right at the edge of detectability with this sample \
             size; more samples per run would give a more decisive answer.",
            style::warn_mark(),
            outcomes.len()
        );
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Check {
            url,
            header,
            query,
            json_field,
            json_body,
            secret,
            secret_env,
            secret_stdin,
            value_a,
            value_b,
            samples,
            max_samples,
            pilot_samples,
            block_size,
            confidence,
            percentile,
            insecure,
            extra_headers,
            output_csv,
            report,
            seed,
            force,
            repeat,
        } => {
            if json_body.is_some() && json_field.is_none() {
                anyhow::bail!(
                    "--json-body requires --json-field (it fills in the rest of the JSON \
                     body around the field --json-field injects into; without --json-field \
                     there's nothing to inject)"
                );
            }
            let injection = if let Some(name) = header {
                InjectionPoint::Header(name)
            } else if let Some(name) = query {
                InjectionPoint::Query(name)
            } else if let Some(name) = json_field {
                let template = match json_body {
                    Some(raw) => {
                        let value: serde_json::Value =
                            serde_json::from_str(&raw).context("--json-body is not valid JSON")?;
                        let mut obj = value.as_object().cloned().context(
                            "--json-body must be a JSON object, e.g. '{\"username\": \"admin\"}'",
                        )?;
                        obj.remove(&name);
                        Some(obj)
                    }
                    None => None,
                };
                InjectionPoint::JsonBody {
                    field: name,
                    template,
                }
            } else {
                unreachable!("clap ArgGroup guarantees exactly one injection point")
            };

            // fix the seed before the first RNG use, so the whole run
            // (wrong-value generation + request interleaving order) is
            // reproducible from the one number printed in the report.
            let seed = seed.unwrap_or_else(|| rand::thread_rng().gen());
            let mut rng = StdRng::seed_from_u64(seed);

            let resolved_secret = read_secret(secret, secret_env, secret_stdin)?;
            let (val_a, val_b) = if let Some(secret) = resolved_secret {
                let wrong = sampler::random_wrong_value(&secret, &mut rng);
                eprintln!(
                    "generated wrong value of matching length: {} bytes",
                    wrong.len()
                );
                (wrong, secret)
            } else {
                let b = value_b.expect("clap group guarantees value_b when no secret source given");
                let a = match value_a {
                    Some(a) => a,
                    None => {
                        eprintln!(
                            "--value-b given without --value-a, generating a random wrong value"
                        );
                        sampler::random_wrong_value(&b, &mut rng)
                    }
                };
                (a, b)
            };

            if val_a.len() != val_b.len() {
                style::warning(&format!(
                    "the two tested values have different lengths ({} vs {} bytes). \
                     This alone can cause a timing difference unrelated to any comparison leak, \
                     and will confound the result.",
                    val_a.len(),
                    val_b.len()
                ));
            }
            eprintln!(
                "{}",
                style::bold().apply_to(
                    "sidecheck: only test systems you own or have explicit permission to test."
                )
            );
            eprintln!("seed: {seed} (pass --seed {seed} to reproduce this exact request order)\n");
            let injection_desc = injection.describe();
            eprintln!("injection point: {}\n", injection_desc);

            let target = sampler::HttpTarget::new_with_options(
                &url,
                injection,
                insecure,
                parse_extra_headers(&extra_headers)?,
            )?;
            let repeat = repeat.max(1);

            let mut outcomes: Vec<(RunResult, DetectionReport)> = Vec::with_capacity(repeat);

            for i in 0..repeat {
                if repeat > 1 {
                    println!("\n=== run {}/{repeat} ===", i + 1);
                }

                let run = run_one_check(
                    &target,
                    &val_a,
                    &val_b,
                    pilot_samples,
                    block_size,
                    max_samples,
                    samples,
                    percentile,
                    confidence,
                    force,
                    repeat == 1,
                    &mut rng,
                )?;

                if let Some(path) = &output_csv {
                    let path = suffix_path(path, repeat, i);
                    export::write_csv(&path, &run.raw)?;
                    eprintln!("raw samples written to {}", path.display());
                }

                let detection_report = DetectionReport {
                    target: url.clone(),
                    field: injection_desc.clone(),
                    samples_per_class: run.samples_per_class,
                    result: run.result.clone(),
                    jitter_seconds: run.jitter_seconds,
                    failures: run.raw.failures,
                    seed,
                    sidecheck_version: env!("CARGO_PKG_VERSION").to_string(),
                };
                println!("{}", render::detection(&detection_report));

                if let Some(path) = &report {
                    let path = suffix_path(path, repeat, i);
                    export::write_json(&path, &detection_report)?;
                    eprintln!("JSON report written to {}", path.display());
                }

                outcomes.push((run, detection_report));
            }

            if repeat > 1 {
                print_stability_summary(&outcomes);
            }

            Ok(())
        }

        Commands::Doctor {
            url,
            samples,
            insecure,
            extra_headers,
        } => {
            // doctor doesn't compare classes — it just sends the same
            // harmless request n times and looks at the shape of the
            // distribution.
            let injection = InjectionPoint::Header("X-Sidecheck-Doctor".to_string());
            let target = sampler::HttpTarget::new_with_options(
                &url,
                injection,
                insecure,
                parse_extra_headers(&extra_headers)?,
            )?;

            eprintln!("probing {url} ({samples} requests)...");
            let pb = ProgressBar::new(samples as u64);
            pb.set_style(ProgressStyle::with_template("{bar:40} {pos}/{len} requests").unwrap());
            let result = sampler::collect_plain(&target, "probe", samples, |done, total| {
                pb.set_position(done as u64);
                pb.set_length(total as u64);
            });
            pb.finish_and_clear();

            if result.latencies.is_empty() {
                style::fatal(
                    &format!("all {samples} requests failed — can't reach {url} at all."),
                    Some(
                        "check the URL is reachable (curl it directly), and that --insecure \
                         isn't needed for a self-signed cert.",
                    ),
                );
            }

            let doctor_report =
                DoctorReport::from_measurements(url, &result.latencies, result.failures);
            println!("{}", render::doctor(&doctor_report));

            Ok(())
        }

        Commands::Compare { baseline, current } => {
            let base = export::read_json(&baseline)?;
            let cur = export::read_json(&current)?;

            if base.target != cur.target || base.injection_point != cur.injection_point {
                style::warning(&format!(
                    "comparing reports for different targets/injection points —\n  \
                     baseline: {} ({})\n  current:  {} ({})\n  \
                     this comparison may not be meaningful.",
                    base.target, base.injection_point, cur.target, cur.injection_point
                ));
            }

            println!("{}", render::compare(&base, &cur));

            if render::compare_is_regression(&base, &cur) {
                std::process::exit(1);
            }

            Ok(())
        }
    }
}
