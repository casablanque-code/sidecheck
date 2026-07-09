use anyhow::Result;
use clap::{ArgGroup, Parser, Subcommand};
use indicatif::{ProgressBar, ProgressStyle};
use sidecheck_core::{export, report::DetectionReport, sampler::{self, InjectionPoint}, stats};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "sidecheck", version, about = "Timing side-channel auditor for your own services")]
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
            .args(["secret", "value_b"])
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

        /// Простой режим: твой настоящий секрет. Неверное значение той же
        /// длины сгенерируется автоматически.
        #[arg(long)]
        secret: Option<String>,
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
    },
}

/// Минимум сэмплов на класс — ниже этого низкий перцентиль статистически
/// шаткий, даже если формула по джиттеру говорит, что для обнаружения
/// эффекта такого размера хватило бы меньшего числа.
const MIN_SAMPLES: usize = 200;

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Check {
            url, header, query, json_field, secret, value_a, value_b,
            samples, max_samples, pilot_samples, block_size, confidence, percentile, insecure,
            output_csv,
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

            let (val_a, val_b) = if let Some(secret) = secret {
                let wrong = sampler::random_wrong_value(&secret);
                eprintln!("generated wrong value of matching length: {} bytes", wrong.len());
                (wrong, secret)
            } else {
                let b = value_b.expect("clap group guarantees value_b when secret is absent");
                let a = match value_a {
                    Some(a) => a,
                    None => {
                        eprintln!("--value-b given without --value-a, generating a random wrong value");
                        sampler::random_wrong_value(&b)
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
            eprintln!("sidecheck: only test systems you own or have explicit permission to test.\n");
            let injection_desc = injection.describe();
            eprintln!("injection point: {}\n", injection_desc);

            let target = sampler::HttpTarget::new_with_options(&url, injection, insecure)?;

            eprintln!("running pilot batch ({pilot_samples} samples/class) to estimate network jitter...");
            let pilot = sampler::run_interleaved(&target, &val_a, &val_b, pilot_samples, block_size, |_, _| {})?;
            let mut combined_pilot = pilot.class_a.clone();
            combined_pilot.extend(&pilot.class_b);
            let jitter = stats::estimate_jitter(&combined_pilot, percentile);

            let pilot_result = stats::box_test(&pilot.class_a, &pilot.class_b, percentile, confidence);
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
                        eprintln!(
                            "warning: network jitter ({:.2} ms) is large relative to the \
                             estimated effect ({:.1} μs). {} samples would be needed for a \
                             clean signal, capping at --max-samples={}. The result may be \
                             inconclusive — consider testing over a lower-latency network \
                             (e.g. same LAN as the target) or raising --max-samples.",
                            jitter * 1000.0, pilot_leak * 1_000_000.0, needed, max_samples
                        );
                        max_samples.max(MIN_SAMPLES)
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
            let raw = sampler::run_interleaved(&target, &val_a, &val_b, effective_samples, block_size, |done, total| {
                pb.set_position(done as u64);
                pb.set_length(total as u64);
            })?;
            pb.finish_and_clear();

            if let Some(path) = &output_csv {
                export::write_csv(path, &raw)?;
                eprintln!("raw samples written to {}", path.display());
            }

            let result = stats::box_test(&raw.class_a, &raw.class_b, percentile, confidence);
            let report = DetectionReport {
                target: url,
                field: injection_desc,
                samples_per_class: effective_samples,
                result,
                jitter_seconds: jitter,
                failures: raw.failures,
            };
            println!("{}", report.render());

            Ok(())
        }
    }
}
