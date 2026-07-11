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
// Commands парсится и матчится один раз при старте, не хранится в
// коллекциях и не в горячем пути — разница в размере вариантов (Check
// заметно больше Doctor) здесь не имеет практического значения. Боксинг
// отдельных полей ради этого линта добавил бы косвенность без реальной
// выгоды.
#[allow(clippy::large_enum_variant)]
enum Commands {
    /// Проверить HTTP-эндпоинт на timing side-channel
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
        /// URL эндпоинта, например https://myapp.local/login
        url: String,

        /// Подставлять значение в HTTP-заголовок с этим именем
        #[arg(long, value_name = "NAME")]
        header: Option<String>,
        /// Подставлять значение в query-параметр с этим именем (GET ?name=value)
        #[arg(long, value_name = "NAME")]
        query: Option<String>,
        /// Подставлять значение в поле JSON-тела POST-запроса
        #[arg(long, value_name = "NAME")]
        json_field: Option<String>,

        /// Простой режим: твой настоящий секрет прямо аргументом. Виден в
        /// `ps aux` и попадёт в историю шелла — для чувствительных секретов
        /// используй --secret-env или --secret-stdin.
        #[arg(long)]
        secret: Option<String>,
        /// Читать секрет из переменной окружения с этим именем (не светится
        /// в `ps aux`/истории шелла) — предпочтительный способ
        #[arg(long, value_name = "VAR")]
        secret_env: Option<String>,
        /// Прочитать секрет из stdin (одна строка, без переноса) —
        /// удобно для пайпа из password-менеджера: `pass show x | sidecheck ... --secret-stdin`
        #[arg(long, default_value_t = false)]
        secret_stdin: bool,

        /// Продвинутый режим: заведомо неверное значение (класс A)
        #[arg(long, requires = "value_b")]
        value_a: Option<String>,
        /// Продвинутый режим: значение с верным префиксом/полностью верное (класс B)
        #[arg(long)]
        value_b: Option<String>,

        /// Число измерений на класс. Если не указано — подбирается
        /// автоматически по итогам пилотного прогона.
        #[arg(long)]
        samples: Option<usize>,
        /// Потолок для автоматически подобранного числа сэмплов
        #[arg(long, default_value_t = 200_000)]
        max_samples: usize,
        /// Размер пилотного забега для оценки джиттера сети
        #[arg(long, default_value_t = 300)]
        pilot_samples: usize,
        /// Размер блока при рандомизированном чередовании классов
        #[arg(long, default_value_t = 20)]
        block_size: usize,
        /// Уровень доверия для вывода (0.0-1.0)
        #[arg(long, default_value_t = 0.95)]
        confidence: f64,
        /// Низкий перцентиль для box test (по методологии Crosby-Wallach)
        #[arg(long, default_value_t = 10.0)]
        percentile: f64,
        /// Принимать самоподписанные/невалидные TLS-сертификаты (для homelab)
        #[arg(long, default_value_t = false)]
        insecure: bool,
        /// Сохранить сырые измерения в CSV (class,elapsed_seconds) для
        /// независимой перепроверки статистики
        #[arg(long, value_name = "PATH")]
        output_csv: Option<PathBuf>,
        /// Сохранить машиночитаемый JSON-отчёт (для CI/автоматизации)
        #[arg(long, value_name = "PATH")]
        report: Option<PathBuf>,
        /// Seed для генератора случайных чисел — фиксирует порядок
        /// чередования запросов, чтобы прогон можно было точно повторить.
        /// Если не указан, генерируется случайно и печатается в отчёте.
        #[arg(long)]
        seed: Option<u64>,
        /// Всё равно продолжить, даже если по оценке джиттера собранной
        /// при --max-samples мощности заведомо не хватит для значимого
        /// результата (по умолчанию sidecheck в этом случае останавливается,
        /// чтобы не тратить часы на прогон, который всё равно будет inconclusive)
        #[arg(long, default_value_t = false)]
        force: bool,
        /// Прогнать весь эксперимент (пилот + основной замер) N раз подряд
        /// и показать, насколько стабильна оценка утечки между прогонами —
        /// если результат "гуляет" от прогона к прогону, ему нельзя доверять
        /// так же, как стабильному.
        #[arg(long, default_value_t = 1)]
        repeat: usize,
    },

    /// Pre-flight проверка сетевого канала до цели — до того, как тратить
    /// время на полноценный check. Отвечает на вопрос "стоит ли вообще
    /// пытаться измерять timing здесь", а не "есть ли утечка".
    Doctor {
        /// URL цели, например https://myapp.local/login
        url: String,
        /// Число замеров для оценки RTT/джиттера/потерь
        #[arg(long, default_value_t = 300)]
        samples: usize,
        /// Принимать самоподписанные/невалидные TLS-сертификаты
        #[arg(long, default_value_t = false)]
        insecure: bool,
    },
}

/// Минимум сэмплов на класс — ниже этого низкий перцентиль статистически
/// шаткий, даже если формула по джиттеру говорит, что для обнаружения
/// эффекта такого размера хватило бы меньшего числа.
const MIN_SAMPLES: usize = 200;

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
        eprintln!(
            "warning: secret passed via --secret is visible in `ps aux` and shell history. \
             Prefer --secret-env or --secret-stdin for anything sensitive."
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

/// Результат одного полного прогона check (пилот + основной замер).
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

    // Считаем итоговый размер выборки одним проходом и печатаем одно
    // связное сообщение о том, как мы к нему пришли — вместо того чтобы
    // сначала объявить один план, а потом тут же его отменить.
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

                eprintln!(
                    "warning: network jitter ({:.2} ms) is large relative to the \
                     estimated effect ({:.1} μs) — signal-to-noise ratio is roughly \
                     1:{:.0}. {} samples would be needed for a clean signal; \
                     --max-samples={} would still fall far short and the result would \
                     almost certainly be inconclusive.",
                    jitter * 1000.0,
                    pilot_leak * 1_000_000.0,
                    jitter / pilot_leak,
                    needed,
                    max_samples
                );
                eprintln!(
                    "  running the capped {capped} samples/class would take roughly \
                     {} at this network's measured latency, for a result that likely \
                     won't reach significance either way.",
                    format_wall_time(estimated_wall_seconds)
                );

                if !force {
                    eprintln!(
                        "\nstopping before wasting that time. this usually means the \
                         leak (if real) is too small to catch over this network path. \
                         Options:\n  \
                         - test from a lower-latency vantage point (same LAN/datacenter \
                         as the target, or from the server itself against 127.0.0.1)\n  \
                         - if you understand the result will likely be inconclusive and \
                         want to run it anyway, pass --force\n  \
                         - or raise --max-samples if you're willing to wait much longer"
                    );
                    std::process::exit(1);
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

/// При --repeat > 1 нужно разложить вывод (CSV/JSON) по отдельным файлам,
/// иначе каждый следующий прогон затирает предыдущий. Вставляет "-runN"
/// перед расширением; при repeat=1 путь не трогается.
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

/// Печатает, насколько устойчива оценка утечки между независимыми
/// прогонами --repeat. Разброс — не менее важный сигнал, чем сама оценка:
/// если estimated leak "гуляет" от прогона к прогону, доверять ему нельзя
/// так же, как стабильному результату, даже если каждый отдельный прогон
/// формально значим.
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

    println!("\n{}", "─".repeat(48));
    println!("stability summary across {} runs", outcomes.len());
    println!("{}", "─".repeat(48));
    println!();
    println!("significant in {significant_count}/{} runs", outcomes.len());
    println!(
        "estimated leak   mean {} · range [{}, {}] · std dev {}",
        format_duration_public(mean),
        format_duration_public(min),
        format_duration_public(max),
        format_duration_public(std_dev)
    );

    // Значимость — более надёжный сигнал устойчивости, чем относительное
    // отклонение точечной оценки: когда реальной утечки нет, mean крутится
    // около нуля, и любое крошечное абсолютное отклонение даёт огромное
    // отношение std_dev/mean — это не нестабильность, а ожидаемое поведение
    // при отсутствии эффекта. Поэтому сначала смотрим на согласованность
    // вердикта "значимо/не значимо", и только для случая "все прогоны
    // значимы" имеет смысл спрашивать, насколько стабильна сама величина.
    if significant_count == 0 {
        println!(
            "\n✓ consistently no significant difference across {} runs.",
            outcomes.len()
        );
    } else if significant_count == outcomes.len() {
        if std_dev > mean.abs() * 0.5 {
            println!(
                "\n⚠ all runs found a significant effect, but its magnitude varies \
                 substantially between runs (std dev is more than half the mean) — the \
                 direction is consistent, but don't treat any single run's exact number \
                 as precise."
            );
        } else {
            println!("\n✓ consistently significant with a stable magnitude across runs.");
        }
    } else {
        println!(
            "\n⚠ significance is inconsistent across runs ({significant_count}/{} found a \
             signal) — likely sitting right at the edge of detectability with this sample \
             size; more samples per run would give a more decisive answer.",
            outcomes.len()
        );
    }
}

// report.rs's format_duration is private to that module (it's an internal
// formatting detail of DetectionReport::render); this is a small standalone
// copy for the stability summary rather than making it a public API surface
// sidecheck-core has to keep stable just for one CLI-side convenience print.
fn format_duration_public(seconds: f64) -> String {
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

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Check {
            url,
            header,
            query,
            json_field,
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
            output_csv,
            report,
            seed,
            force,
            repeat,
        } => {
            let injection = if let Some(name) = header {
                InjectionPoint::Header(name)
            } else if let Some(name) = query {
                InjectionPoint::Query(name)
            } else if let Some(name) = json_field {
                InjectionPoint::JsonBody(name)
            } else {
                unreachable!("clap ArgGroup guarantees exactly one injection point")
            };

            // seed фиксируем до первого использования RNG, чтобы весь прогон
            // (генерация неверного значения + порядок чередования запросов)
            // был воспроизводим по одному числу, которое печатается в отчёте.
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
                eprintln!(
                    "warning: the two tested values have different lengths ({} vs {} bytes). \
                     This alone can cause a timing difference unrelated to any comparison leak, \
                     and will confound the result.",
                    val_a.len(),
                    val_b.len()
                );
            }
            eprintln!("sidecheck: only test systems you own or have explicit permission to test.");
            eprintln!("seed: {seed} (pass --seed {seed} to reproduce this exact request order)\n");
            let injection_desc = injection.describe();
            eprintln!("injection point: {}\n", injection_desc);

            let target = sampler::HttpTarget::new_with_options(&url, injection, insecure)?;
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
                println!("{}", detection_report.render());

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
        } => {
            // doctor не сравнивает классы — просто гоняет один и тот же
            // безобидный запрос n раз и смотрит на форму распределения.
            let injection = InjectionPoint::Header("X-Sidecheck-Doctor".to_string());
            let target = sampler::HttpTarget::new_with_options(&url, injection, insecure)?;

            eprintln!("probing {url} ({samples} requests)...");
            let pb = ProgressBar::new(samples as u64);
            pb.set_style(ProgressStyle::with_template("{bar:40} {pos}/{len} requests").unwrap());
            let result = sampler::collect_plain(&target, "probe", samples, |done, total| {
                pb.set_position(done as u64);
                pb.set_length(total as u64);
            });
            pb.finish_and_clear();

            if result.latencies.is_empty() {
                eprintln!("error: all {samples} requests failed — can't reach {url} at all.");
                std::process::exit(1);
            }

            let doctor_report =
                DoctorReport::from_measurements(url, &result.latencies, result.failures);
            println!("{}", doctor_report.render());

            Ok(())
        }
    }
}
