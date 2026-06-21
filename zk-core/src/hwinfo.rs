use serde::Serialize;

#[derive(Serialize, Clone)]
pub struct HwInfo {
    pub cpu: String,
    pub ram_mb: u64,
    pub temp_c: Option<f64>,
}

impl HwInfo {
    pub fn collect() -> Self {
        let cpu = read_cpu().unwrap_or_else(|| "Unknown".into());
        let ram_mb = read_ram_mb().unwrap_or(0);
        let temp_c = read_temp_c();
        HwInfo { cpu, ram_mb, temp_c }
    }
}

fn read_cpu() -> Option<String> {
    let txt = std::fs::read_to_string("/proc/cpuinfo").ok()?;
    txt.lines().find(|l| l.starts_with("model name") || l.starts_with("Model"))
        .and_then(|l| l.split(':').nth(1)).map(|s| s.trim().to_string())
}

fn read_ram_mb() -> Option<u64> {
    let txt = std::fs::read_to_string("/proc/meminfo").ok()?;
    let kb: u64 = txt.lines().find(|l| l.starts_with("MemTotal"))?
        .split_whitespace().nth(1)?.parse().ok()?;
    Some(kb / 1024)
}

fn read_temp_c() -> Option<f64> {
    let raw = std::fs::read_to_string("/sys/class/thermal/thermal_zone0/temp").ok()?;
    raw.trim().parse::<f64>().ok().map(|m| m / 1000.0)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn collect_never_panics_and_serializes() {
        let hw = HwInfo::collect();
        let json = serde_json::to_string(&hw).unwrap();
        assert!(json.contains("cpu"));
    }
}
