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

            eprintln!(
                "running pilot batch ({pilot_samples} samples/class) to estimate network jitter..."
            );
            let pilot = sampler::run_interleaved(
                &target,
                &val_a,
                &val_b,
                pilot_samples,
                block_size,
                &mut rng,
                |_, _| {},
            )?;
            let mut combined_pilot = pilot.class_a.clone();
            combined_pilot.extend(&pilot.class_b);
            let jitter = stats::estimate_jitter(&combined_pilot);

            let pilot_result =
                stats::box_test(&pilot.class_a, &pilot.class_b, percentile, confidence);
            let pilot_leak = pilot_result.estimated_leak.abs();

            // Считаем итоговый размер выборки одним проходом и печатаем одно
            // связное сообщение о том, как мы к нему пришли — вместо того
            // чтобы сначала объявить один план, а потом тут же его отменить.
            let effective_samples = match samples {
                Some(n) => {
                    eprintln!("using explicit --samples={n}");
                    n.max(MIN_SAMPLES)
                }
                None if pilot_leak <= 0.0 => {
                    let default_n = MIN_SAMPLES.max(5_000);
                    eprintln!("pilot found no measurable difference; using default sample size ({default_n})");
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
                            pilot_leak * 1_000_000.0, needed
                        );
                        needed as usize
                    }
                }
            };

            let pb = ProgressBar::new((effective_samples * 2) as u64);
            pb.set_style(ProgressStyle::with_template("{bar:40} {pos}/{len} requests").unwrap());
            let raw = sampler::run_interleaved(
                &target,
                &val_a,
                &val_b,
                effective_samples,
                block_size,
                &mut rng,
                |done, total| {
                    pb.set_position(done as u64);
                    pb.set_length(total as u64);
                },
            )?;
            pb.finish_and_clear();

            if let Some(path) = &output_csv {
                export::write_csv(path, &raw)?;
                eprintln!("raw samples written to {}", path.display());
            }

            let result = stats::box_test(&raw.class_a, &raw.class_b, percentile, confidence);
            let detection_report = DetectionReport {
                target: url,
                field: injection_desc,
                samples_per_class: effective_samples,
                result,
                jitter_seconds: jitter,
                failures: raw.failures,
                seed,
                sidecheck_version: env!("CARGO_PKG_VERSION").to_string(),
            };
            println!("{}", detection_report.render());

            if let Some(path) = &report {
                export::write_json(path, &detection_report)?;
                eprintln!("JSON report written to {}", path.display());
            }

            Ok(())
        }

        Commands::Doctor { url, samples, insecure } => {
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

            let doctor_report = DoctorReport::from_measurements(url, &result.latencies, result.failures);
            println!("{}", doctor_report.render());

            Ok(())
        }
    }
}
