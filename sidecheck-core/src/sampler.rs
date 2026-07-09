//! Сбор сырых измерений времени отклика.
//!
//! Ключевое требование методологии: классы запросов (например, "верный
//! префикс" / "неверный префикс") должны чередоваться в случайном порядке,
//! а не идти блоками "сначала все A, потом все B" — иначе на результат
//! повлияет прогрев сервера, фоновая нагрузка или дрейф сети во времени,
//! а не сама утечка. См. dudect / Crosby-Wallach методологию.

use anyhow::{Context, Result};
use rand::seq::SliceRandom;
use rand::Rng;
use std::time::Instant;

/// Куда подставляется тестовое значение. Header — самый частый случай для
/// API-ключей, Query — для legacy-эндпоинтов с токеном в URL, JsonBody —
/// для типичных JSON-логинов (POST /login {"password": "..."}).
#[derive(Clone, Debug)]
pub enum InjectionPoint {
    Header(String),
    Query(String),
    /// Имя поля в плоском JSON-объекте тела запроса
    JsonBody(String),
}

impl InjectionPoint {
    pub fn describe(&self) -> String {
        match self {
            InjectionPoint::Header(n) => format!("header {n}"),
            InjectionPoint::Query(n) => format!("query param {n}"),
            InjectionPoint::JsonBody(n) => format!("JSON field {n}"),
        }
    }
}

/// HTTP-цель: URL и точка, в которую подставляется тестовое значение.
pub struct HttpTarget {
    client: reqwest::blocking::Client,
    url: String,
    injection: InjectionPoint,
}

impl HttpTarget {
    pub fn new(url: impl Into<String>, injection: InjectionPoint) -> Result<Self> {
        Self::new_with_options(url, injection, false)
    }

    pub fn new_with_options(
        url: impl Into<String>,
        injection: InjectionPoint,
        accept_invalid_certs: bool,
    ) -> Result<Self> {
        let client = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            // важно: не подтягивать TCP keep-alive пул иначе первый запрос
            // в каждом классе будет медленнее из-за установки соединения
            .pool_max_idle_per_host(4)
            .danger_accept_invalid_certs(accept_invalid_certs)
            .build()
            .context("failed to build HTTP client")?;
        Ok(Self { client, url: url.into(), injection })
    }

    /// Один замер: отправляет запрос с заданным значением в настроенной
    /// точке инъекции, возвращает время до получения полного ответа в секундах.
    pub fn measure(&self, value: &str) -> Result<f64> {
        let start = Instant::now();

        let resp = match &self.injection {
            InjectionPoint::Header(name) => {
                self.client.get(&self.url).header(name.as_str(), value).send()
            }
            InjectionPoint::Query(name) => {
                self.client.get(&self.url).query(&[(name.as_str(), value)]).send()
            }
            InjectionPoint::JsonBody(field) => {
                let body = serde_json::json!({ field: value });
                self.client.post(&self.url).json(&body).send()
            }
        }
        .context("request failed")?;

        // важно дочитать тело — иначе замер не включает полное время ответа
        let _ = resp.bytes().context("failed to read response body")?;
        Ok(start.elapsed().as_secs_f64())
    }
}

/// Генерирует заведомо неверное значение той же длины, что и реальный
/// секрет — чтобы длина payload не была отдельной переменной, искажающей
/// измерение (см. предупреждение в CLI про разную длину value_a/value_b).
/// Принимает внешний RNG, чтобы весь прогон был воспроизводим по одному seed.
pub fn random_wrong_value(secret: &str, rng: &mut impl Rng) -> String {
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    loop {
        let candidate: String = (0..secret.len())
            .map(|_| CHARSET[rng.gen_range(0..CHARSET.len())] as char)
            .collect();
        if candidate != secret {
            return candidate;
        }
    }
}

#[derive(Debug, Default)]
pub struct RawSamples {
    pub class_a: Vec<f64>,
    pub class_b: Vec<f64>,
    /// число запросов, которые не удалось выполнить (таймаут, разрыв
    /// соединения и т.п.) — не считаются в статистике, но если их много,
    /// результату нельзя доверять
    pub failures: usize,
}

/// Прогоняет n_per_class измерений на каждый класс, чередуя их случайными
/// блоками, чтобы усреднить влияние дрейфа во времени. Одиночные сбои сети
/// не прерывают весь прогон — считаются и репортятся отдельно, но если
/// доля сбоев превышает max_failure_ratio, прогон останавливается: на таком
/// нестабильном канале доверять таймингам нельзя.
pub fn run_interleaved(
    target: &HttpTarget,
    value_a: &str,
    value_b: &str,
    n_per_class: usize,
    block_size: usize,
    rng: &mut impl Rng,
    mut on_progress: impl FnMut(usize, usize),
) -> Result<RawSamples> {
    const MAX_FAILURE_RATIO: f64 = 0.1;

    let mut result = RawSamples::default();
    let mut remaining_a = n_per_class;
    let mut remaining_b = n_per_class;
    let total = n_per_class * 2;
    let mut done = 0;

    while remaining_a > 0 || remaining_b > 0 {
        let mut block: Vec<bool> = Vec::new(); // true = class A
        block.extend(std::iter::repeat(true).take(block_size.min(remaining_a)));
        block.extend(std::iter::repeat(false).take(block_size.min(remaining_b)));
        block.shuffle(rng);

        for is_a in block {
            let measurement = if is_a {
                remaining_a -= 1;
                target.measure(value_a)
            } else {
                remaining_b -= 1;
                target.measure(value_b)
            };

            match measurement {
                Ok(elapsed) => {
                    if is_a {
                        result.class_a.push(elapsed);
                    } else {
                        result.class_b.push(elapsed);
                    }
                }
                Err(_) => {
                    result.failures += 1;
                }
            }

            done += 1;
            on_progress(done, total);

            let attempted = result.class_a.len() + result.class_b.len() + result.failures;
            if attempted > 100 && (result.failures as f64 / attempted as f64) > MAX_FAILURE_RATIO {
                anyhow::bail!(
                    "aborting: {} of {} requests failed ({}%). the target or network is too \
                     unstable for a reliable measurement — fix connectivity first.",
                    result.failures,
                    attempted,
                    (result.failures as f64 / attempted as f64 * 100.0) as u32
                );
            }
        }
    }

    Ok(result)
}
