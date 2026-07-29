//! Collects raw response-time measurements.
//!
//! Key methodology requirement: request classes (e.g. "correct prefix" /
//! "wrong prefix") must be interleaved in random order, not sent block by
//! block ("all A, then all B") — otherwise server warm-up, background
//! load, or network drift over time bias the result, not the leak itself.
//! See the dudect / Crosby-Wallach methodology.

use anyhow::{Context, Result};
use rand::seq::SliceRandom;
use rand::Rng;
use std::time::Instant;

/// Where the test value gets injected. Header is the most common case for
/// API keys, Query for legacy endpoints with a token in the URL, JsonBody
/// for typical JSON logins (POST /login {"password": "..."}).
#[derive(Clone, Debug)]
pub enum InjectionPoint {
    Header(String),
    Query(String),
    /// Name of the field in the JSON request body, plus an optional
    /// template for the rest of the fields (e.g. {"username": "admin"})
    /// the backend needs to even reach the secret comparison. If no
    /// template is given, the body is just this one field, as before.
    JsonBody {
        field: String,
        template: Option<serde_json::Map<String, serde_json::Value>>,
    },
}

impl InjectionPoint {
    pub fn describe(&self) -> String {
        match self {
            InjectionPoint::Header(n) => format!("header {n}"),
            InjectionPoint::Query(n) => format!("query param {n}"),
            InjectionPoint::JsonBody { field, template } => match template {
                Some(_) => format!("JSON field {field} (with body template)"),
                None => format!("JSON field {field}"),
            },
        }
    }
}

/// HTTP target: the URL, the point where the test value gets injected,
/// and any static headers sent unchanged on every request (auth headers,
/// CSRF tokens, session cookies — whatever the endpoint needs to reach
/// the code path under test at all, distinct from the value being
/// injected and measured).
pub struct HttpTarget {
    client: reqwest::blocking::Client,
    url: String,
    injection: InjectionPoint,
    extra_headers: Vec<(String, String)>,
}

impl HttpTarget {
    pub fn new(url: impl Into<String>, injection: InjectionPoint) -> Result<Self> {
        Self::new_with_options(url, injection, false, Vec::new())
    }

    pub fn new_with_options(
        url: impl Into<String>,
        injection: InjectionPoint,
        accept_invalid_certs: bool,
        extra_headers: Vec<(String, String)>,
    ) -> Result<Self> {
        let client = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            // important: keep the TCP keep-alive pool small, otherwise the
            // first request in each class is slower due to connection setup
            .pool_max_idle_per_host(4)
            .danger_accept_invalid_certs(accept_invalid_certs)
            .build()
            .context("failed to build HTTP client")?;
        Ok(Self {
            client,
            url: url.into(),
            injection,
            extra_headers,
        })
    }

    /// One measurement: sends a request with the given value at the
    /// configured injection point, returns the time to receive the full
    /// response, in seconds.
    pub fn measure(&self, value: &str) -> Result<f64> {
        let start = Instant::now();

        let builder = match &self.injection {
            InjectionPoint::Header(name) => self.client.get(&self.url).header(name.as_str(), value),
            InjectionPoint::Query(name) => {
                self.client.get(&self.url).query(&[(name.as_str(), value)])
            }
            InjectionPoint::JsonBody { field, template } => {
                let mut body = template.clone().unwrap_or_default();
                body.insert(field.clone(), serde_json::Value::String(value.to_string()));
                self.client
                    .post(&self.url)
                    .json(&serde_json::Value::Object(body))
            }
        };

        let builder = self
            .extra_headers
            .iter()
            .fold(builder, |b, (name, value)| b.header(name, value));

        let resp = builder.send().context("request failed")?;

        // important to read the body fully — otherwise the measurement
        // doesn't include the full response time
        let _ = resp.bytes().context("failed to read response body")?;
        Ok(start.elapsed().as_secs_f64())
    }
}

/// Generates a deliberately wrong value of the same length as the real
/// secret — so payload length isn't a separate variable skewing the
/// measurement (see the CLI warning about mismatched value_a/value_b
/// length). Takes an external RNG so the whole run is reproducible from
/// one seed.
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
    /// number of requests that couldn't be completed (timeout, connection
    /// reset, etc.) — not counted in the statistics, but if there are many
    /// of them, the result can't be trusted
    pub failures: usize,
}

/// Runs n_per_class measurements for each class, interleaving them in
/// random blocks to average out drift over time. Isolated network
/// failures don't abort the whole run — they're counted and reported
/// separately, but if the failure ratio exceeds max_failure_ratio, the run
/// stops: timings can't be trusted over such an unstable channel.
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
        block.extend(std::iter::repeat_n(true, block_size.min(remaining_a)));
        block.extend(std::iter::repeat_n(false, block_size.min(remaining_b)));
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

/// Result of a plain measurement pass for `sidecheck doctor` — no class
/// split, we only care about the shape of the RTT distribution to the
/// target.
#[derive(Debug, Default)]
pub struct PlainSamples {
    pub latencies: Vec<f64>,
    pub failures: usize,
}

/// Collects n consecutive measurements of the same request. Unlike
/// run_interleaved, it doesn't abort on packet loss — it just counts it:
/// in doctor mode, the loss rate itself is part of the diagnosis, not a
/// reason to stop.
pub fn collect_plain(
    target: &HttpTarget,
    value: &str,
    n: usize,
    mut on_progress: impl FnMut(usize, usize),
) -> PlainSamples {
    let mut result = PlainSamples::default();
    for i in 0..n {
        match target.measure(value) {
            Ok(elapsed) => result.latencies.push(elapsed),
            Err(_) => result.failures += 1,
        }
        on_progress(i + 1, n);
    }
    result
}
