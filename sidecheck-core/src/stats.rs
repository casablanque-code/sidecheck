//! Статистическое ядро sidecheck.
//!
//! Методология основана на Crosby, Wallach, Riedi, "Opportunities and Limits
//! of Remote Timing Attacks" (ACM TISSEC, 2009): сеть может только добавлять
//! задержку, никогда не убирать её, поэтому нижние перцентили выборки несут
//! значительно меньше шума, чем среднее или даже минимум по сырым данным.
//! На этом строится "box test" — сравнение низких перцентилей двух выборок.

/// Число итераций bootstrap resampling для доверительного интервала.
/// Вынесено в константу, чтобы её можно было честно указать в отчёте —
/// не просто "confidence: 95%", а явно "bootstrap confidence на N итерациях".
pub const BOOTSTRAP_ITERATIONS: usize = 2000;

use rand::Rng;

/// Возвращает значение p-го перцентиля отсортированной выборки (p в [0.0, 100.0]).
pub fn percentile(sorted: &[f64], p: f64) -> f64 {
    assert!(!sorted.is_empty(), "empty sample");
    let idx = (p / 100.0 * (sorted.len() - 1) as f64).round() as usize;
    sorted[idx.min(sorted.len() - 1)]
}

fn sorted_copy(data: &[f64]) -> Vec<f64> {
    let mut v = data.to_vec();
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    v
}

/// Результат box test: разница между низкими перцентилями двух выборок
/// плюс доверительный интервал, полученный бутстрэпом (без предположений
/// о нормальности распределения сетевых задержек).
#[derive(Debug, Clone)]
pub struct BoxTestResult {
    pub class_a_low_percentile: f64,
    pub class_b_low_percentile: f64,
    /// class_b - class_a, в тех же единицах, что и входные данные (секунды)
    pub estimated_leak: f64,
    pub ci_low: f64,
    pub ci_high: f64,
    pub confidence: f64,
}

impl BoxTestResult {
    /// Утечка считается статистически значимой, если доверительный интервал
    /// разницы не содержит нуля.
    pub fn is_significant(&self) -> bool {
        self.ci_low > 0.0 || self.ci_high < 0.0
    }
}

/// Box test по методологии Crosby-Wallach: сравнивает низкий перцентиль
/// (по умолчанию p10) двух выборок времени отклика, доверительный интервал
/// строится через bootstrap resampling.
pub fn box_test(class_a: &[f64], class_b: &[f64], low_percentile: f64, confidence: f64) -> BoxTestResult {
    let a_sorted = sorted_copy(class_a);
    let b_sorted = sorted_copy(class_b);

    let a_p = percentile(&a_sorted, low_percentile);
    let b_p = percentile(&b_sorted, low_percentile);
    let leak = b_p - a_p;

    let (ci_low, ci_high) = bootstrap_ci(class_a, class_b, low_percentile, confidence, BOOTSTRAP_ITERATIONS);

    BoxTestResult {
        class_a_low_percentile: a_p,
        class_b_low_percentile: b_p,
        estimated_leak: leak,
        ci_low,
        ci_high,
        confidence,
    }
}

/// Bootstrap-доверительный интервал для разницы низких перцентилей.
/// Не полагается на нормальность — пересэмплирует исходные данные с
/// возвращением и считает эмпирическое распределение разницы.
fn bootstrap_ci(class_a: &[f64], class_b: &[f64], p: f64, confidence: f64, iterations: usize) -> (f64, f64) {
    let mut rng = rand::thread_rng();
    let mut diffs = Vec::with_capacity(iterations);

    for _ in 0..iterations {
        let resample_a = resample(class_a, &mut rng);
        let resample_b = resample(class_b, &mut rng);
        let pa = percentile(&sorted_copy(&resample_a), p);
        let pb = percentile(&sorted_copy(&resample_b), p);
        diffs.push(pb - pa);
    }

    diffs.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let alpha = 1.0 - confidence;
    let lo_idx = ((alpha / 2.0) * diffs.len() as f64) as usize;
    let hi_idx = (((1.0 - alpha / 2.0) * diffs.len() as f64) as usize).min(diffs.len() - 1);
    (diffs[lo_idx], diffs[hi_idx])
}

fn resample(data: &[f64], rng: &mut impl Rng) -> Vec<f64> {
    (0..data.len()).map(|_| data[rng.gen_range(0..data.len())]).collect()
}

/// Оценка джиттера сети по пилотной выборке — стандартное отклонение
/// низкого перцентиля, используется для оценки необходимого числа сэмплов.
pub fn estimate_jitter(pilot: &[f64], low_percentile: f64) -> f64 {
    let sorted = sorted_copy(pilot);
    let p = percentile(&sorted, low_percentile);
    let variance: f64 = pilot.iter().map(|x| (x - p).powi(2)).sum::<f64>() / pilot.len() as f64;
    variance.sqrt()
}

/// Оценка минимального числа запросов на класс, необходимого для
/// обнаружения утечки заданного размера при данном уровне шума сети.
/// Формула из мощностного анализа (power analysis) для сравнения средних:
/// n ≈ 2 * (z_alpha/2 + z_beta)^2 * sigma^2 / delta^2
pub fn required_samples(jitter: f64, expected_leak_seconds: f64, confidence: f64) -> u64 {
    if expected_leak_seconds <= 0.0 {
        return u64::MAX;
    }
    // z-значения для двустороннего теста с confidence и мощностью 80% (z_beta ≈ 0.84)
    let z_alpha = inverse_normal_cdf(1.0 - (1.0 - confidence) / 2.0);
    let z_beta = 0.84;
    let n = 2.0 * (z_alpha + z_beta).powi(2) * jitter.powi(2) / expected_leak_seconds.powi(2);
    n.ceil() as u64
}

/// Приближение обратной функции нормального распределения (Beasley-Springer-Moro).
/// Достаточно точное для оценки необходимого объёма выборки.
fn inverse_normal_cdf(p: f64) -> f64 {
    // Rational approximation, максимальная погрешность ~1.15e-9
    let a = [
        -3.969683028665376e+01, 2.209460984245205e+02, -2.759285104469687e+02,
        1.383577518672690e+02, -3.066479806614716e+01, 2.506628277459239e+00,
    ];
    let b = [
        -5.447609879822406e+01, 1.615858368580409e+02, -1.556989798598866e+02,
        6.680131188771972e+01, -1.328068155288572e+01,
    ];
    let c = [
        -7.784894002430293e-03, -3.223964580411365e-01, -2.400758277161838e+00,
        -2.549732539343734e+00, 4.374664141464968e+00, 2.938163982698783e+00,
    ];
    let d = [
        7.784695709041462e-03, 3.224671290700398e-01, 2.445134137142996e+00,
        3.754408661907416e+00,
    ];
    let p_low = 0.02425;
    let p_high = 1.0 - p_low;

    if p < p_low {
        let q = (-2.0 * p.ln()).sqrt();
        (((((c[0] * q + c[1]) * q + c[2]) * q + c[3]) * q + c[4]) * q + c[5])
            / ((((d[0] * q + d[1]) * q + d[2]) * q + d[3]) * q + 1.0)
    } else if p <= p_high {
        let q = p - 0.5;
        let r = q * q;
        (((((a[0] * r + a[1]) * r + a[2]) * r + a[3]) * r + a[4]) * r + a[5]) * q
            / (((((b[0] * r + b[1]) * r + b[2]) * r + b[3]) * r + b[4]) * r + 1.0)
    } else {
        let q = (-2.0 * (1.0 - p).ln()).sqrt();
        -(((((c[0] * q + c[1]) * q + c[2]) * q + c[3]) * q + c[4]) * q + c[5])
            / ((((d[0] * q + d[1]) * q + d[2]) * q + d[3]) * q + 1.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn percentile_basic() {
        let data = vec![1.0, 2.0, 3.0, 4.0, 5.0];
        assert_eq!(percentile(&data, 0.0), 1.0);
        assert_eq!(percentile(&data, 100.0), 5.0);
        assert_eq!(percentile(&data, 50.0), 3.0);
    }

    #[test]
    fn box_test_detects_no_difference() {
        let a: Vec<f64> = (0..1000).map(|i| 0.010 + (i as f64 % 7.0) * 0.0001).collect();
        let b = a.clone();
        let result = box_test(&a, &b, 10.0, 0.95);
        assert!(!result.is_significant(), "identical samples must not be significant");
    }

    #[test]
    fn box_test_detects_real_difference() {
        let a: Vec<f64> = (0..2000).map(|i| 0.010 + (i as f64 % 11.0) * 0.0002).collect();
        let b: Vec<f64> = (0..2000).map(|i| 0.010 + 0.0005 + (i as f64 % 11.0) * 0.0002).collect();
        let result = box_test(&a, &b, 10.0, 0.95);
        assert!(result.is_significant(), "clear 0.5ms shift must be detected");
        assert!(result.estimated_leak > 0.0);
    }
}
