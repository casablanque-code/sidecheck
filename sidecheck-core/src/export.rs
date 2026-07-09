//! Экспорт сырых измерений — чтобы результат можно было приложить к PR или
//! bug bounty репорту и дать кому угодно перепроверить статистику самому,
//! не доверяя вердикту sidecheck на слово.

use crate::sampler::RawSamples;
use anyhow::{Context, Result};
use std::io::Write;
use std::path::Path;

pub fn write_csv(path: &Path, raw: &RawSamples) -> Result<()> {
    let mut file = std::fs::File::create(path)
        .with_context(|| format!("failed to create {}", path.display()))?;

    writeln!(file, "class,elapsed_seconds")?;
    for v in &raw.class_a {
        writeln!(file, "a,{v:.9}")?;
    }
    for v in &raw.class_b {
        writeln!(file, "b,{v:.9}")?;
    }

    Ok(())
}
