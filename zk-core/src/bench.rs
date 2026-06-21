//! Benchmark harness: sweep the (circuit, k) matrix through the real Halo2 IPA
//! proving pipeline and capture genuine timings, proof sizes, peak memory, modeled
//! energy, and verification outcomes.
//!
//! Every row is produced by actually running [`crate::prover::run_proof`] — no
//! timing or size value here is fabricated. The resulting [`BenchResults`]
//! serializes to the JSON that backs the README results table (Pi vs laptop),
//! which is the core grant evidence.
//!
//! ## Per-row memory isolation
//!
//! `peak_rss_kb` is read from `/proc/self/status` `VmHWM`, a *process-wide*
//! high-water mark. If every row ran in one process, later rows would inherit the
//! peak of earlier rows. To get a genuine per-row figure, [`run_bench`] runs each
//! point in its **own subprocess** (re-invoking this binary's `bench-one`
//! subcommand) and reads that fresh process's `VmHWM`. Each [`BenchRow`] therefore
//! reflects the isolated peak of exactly one (circuit, k) proving run.
//!
//! ## Modeled energy (honest caveat)
//!
//! A Raspberry Pi 3B has no on-board power sensor and the Cortex-A53 exposes no
//! RAPL counters, so energy here is **modeled, not measured**: `proof_energy_j =
//! assumed_power_w * proof_ms / 1000`. The wall-clock `proof_ms` is real; the
//! power figure is an assumption ([`DEFAULT_POWER_W`], overridable via the
//! `ZK_BENCH_POWER_W` environment variable). To report a true figure, measure
//! board power with an inline USB meter while proving and set `ZK_BENCH_POWER_W`.

use serde::{Deserialize, Serialize};

use crate::circuit::cubic::CubicCircuit;
use crate::circuit::merkle::{MerkleCircuit, MERKLE_K};
use crate::circuit::poseidon::{PoseidonCircuit, POSEIDON_K};
use crate::hwinfo::HwInfo;
use crate::prover::{run_proof, ProofRun};
use pasta_curves::Fp;

/// Default assumed active board power (W) for the modeled energy metric, used when
/// `ZK_BENCH_POWER_W` is unset. 3.0 W is a conservative Raspberry Pi 3B under full
/// CPU load (idle ~1.6 W; load typically 2.6–3.8 W with no peripherals attached).
/// This is a MODEL, not a meter reading — set `ZK_BENCH_POWER_W` to your measured
/// wattage to get a real energy figure.
pub const DEFAULT_POWER_W: f64 = 3.0;

/// The default benchmark sweep: each circuit at its minimum synthesizable `k` and
/// one step larger. Merkle is the heavy, Zcash-relevant workload (8 sequential
/// Poseidon hashes), so its peak memory and energy dominate — which is the point.
pub const SWEEP: &[(&str, u32)] = &[
    ("cubic", 4),
    ("cubic", 8),
    ("poseidon", POSEIDON_K),
    ("poseidon", POSEIDON_K + 1),
    ("merkle", MERKLE_K),
    ("merkle", MERKLE_K + 1),
];

/// One measured proving run for a given (circuit, k) point in the sweep.
#[derive(Serialize, Deserialize, Clone)]
pub struct BenchRow {
    /// Circuit name: `"cubic"`, `"poseidon"`, or `"merkle"`.
    pub circuit: String,
    /// Domain-size parameter (`2^k` rows).
    pub k: u32,
    /// Keygen (setup) time, in ms.
    pub setup_ms: f64,
    /// Proof-generation time, in ms.
    pub proof_ms: f64,
    /// Verification time, in ms.
    pub verify_ms: f64,
    /// Serialized proof size, in bytes.
    pub proof_bytes: usize,
    /// Peak resident set size (`VmHWM`) of the isolated subprocess that produced
    /// this row, in KiB. See the module docs for the isolation mechanism.
    pub peak_rss_kb: u64,
    /// Assumed active board power (W) used for the modeled energy figures.
    pub assumed_power_w: f64,
    /// Modeled energy to produce this proof, in joules (`assumed_power_w *
    /// proof_ms / 1000`). MODEL, not a meter reading — see module docs.
    pub proof_energy_j: f64,
    /// Modeled proofs per joule (`1 / proof_energy_j`).
    pub proofs_per_joule: f64,
    /// Whether verification succeeded.
    pub verified: bool,
}

/// Full benchmark output: the host hardware description plus one row per
/// (circuit, k) point in the sweep.
#[derive(Serialize)]
pub struct BenchResults {
    /// Host hardware (CPU/RAM/temp), collected once.
    pub hwinfo: HwInfo,
    /// Measured rows, in sweep order.
    pub rows: Vec<BenchRow>,
}

/// Read the process-wide peak resident set size (`VmHWM`) from
/// `/proc/self/status`, in KiB; returns 0 if unavailable.
///
/// Because [`run_bench`] runs each row in its own subprocess, the value read here
/// is the isolated peak of a single proving run.
fn peak_rss_kb() -> u64 {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|t| {
            t.lines()
                .find(|l| l.starts_with("VmHWM"))
                .and_then(|l| l.split_whitespace().nth(1))
                .and_then(|v| v.parse().ok())
        })
        .unwrap_or(0)
}

/// Active power (W) used for the modeled energy metric: `ZK_BENCH_POWER_W` if set
/// and parseable, otherwise [`DEFAULT_POWER_W`].
fn assumed_power_w() -> f64 {
    std::env::var("ZK_BENCH_POWER_W")
        .ok()
        .and_then(|s| s.parse::<f64>().ok())
        .filter(|w| *w > 0.0)
        .unwrap_or(DEFAULT_POWER_W)
}

/// Run the genuine IPA pipeline for a named circuit at domain size `k`, using each
/// circuit's canonical sample witness. Unknown names fall back to `cubic`, so this
/// never panics on user input. Shared by the `prove`, `bench`, and `bench-one`
/// CLI paths.
pub fn prove_named(circuit: &str, k: u32) -> Result<ProofRun, String> {
    match circuit {
        "poseidon" => {
            let (c, hash) = PoseidonCircuit::sample();
            run_proof(k, &c, &[hash])
        }
        "merkle" => {
            let (c, root) = MerkleCircuit::sample();
            run_proof(k, &c, &[root])
        }
        _ => {
            let c = CubicCircuit { x: Some(Fp::from(3)) };
            run_proof(k, &c, &[Fp::from(35)])
        }
    }
}

/// Produce a single benchmark row in-process: run the proof, then read this
/// process's peak RSS and compute the modeled energy. Intended to be called once
/// per process (that is what gives `peak_rss_kb` its per-row meaning), which is
/// exactly how the `bench-one` subcommand uses it.
pub fn run_one_row(circuit: &str, k: u32) -> Result<BenchRow, String> {
    let run = prove_named(circuit, k)?;
    let power_w = assumed_power_w();
    let proof_energy_j = power_w * run.proof_ms / 1000.0;
    let proofs_per_joule = if proof_energy_j > 0.0 {
        1.0 / proof_energy_j
    } else {
        0.0
    };
    Ok(BenchRow {
        circuit: circuit.to_string(),
        k,
        setup_ms: run.setup_ms,
        proof_ms: run.proof_ms,
        verify_ms: run.verify_ms,
        proof_bytes: run.proof_bytes,
        peak_rss_kb: peak_rss_kb(),
        assumed_power_w: power_w,
        proof_energy_j,
        proofs_per_joule,
        verified: run.verified,
    })
}

/// Run the full benchmark sweep with per-row memory isolation.
///
/// For each [`SWEEP`] point this re-invokes the current executable's `bench-one`
/// subcommand in a fresh subprocess, then parses the single-row JSON it prints.
/// Running each point in its own process makes `peak_rss_kb` a genuine per-row
/// measurement rather than a monotonic high-water mark.
pub fn run_bench() -> BenchResults {
    let hwinfo = HwInfo::collect();
    let exe = std::env::current_exe().expect("locate current executable for bench-one");
    let mut rows = Vec::new();

    for (circuit, k) in SWEEP.iter().copied() {
        let out = std::process::Command::new(&exe)
            .arg("bench-one")
            .arg("--circuit")
            .arg(circuit)
            .arg("--k")
            .arg(k.to_string())
            .output()
            .unwrap_or_else(|e| panic!("failed to spawn bench-one for {circuit} k={k}: {e}"));

        if !out.status.success() {
            panic!(
                "bench-one {circuit} k={k} failed: {}",
                String::from_utf8_lossy(&out.stderr)
            );
        }

        let row: BenchRow = serde_json::from_slice(&out.stdout).unwrap_or_else(|e| {
            panic!(
                "could not parse bench-one output for {circuit} k={k}: {e}; stdout={}",
                String::from_utf8_lossy(&out.stdout)
            )
        });
        rows.push(row);
    }

    BenchResults { hwinfo, rows }
}

/// Serialize `results` to pretty JSON and write it to `path`.
pub fn write_json(results: &BenchResults, path: &str) -> std::io::Result<()> {
    let json = serde_json::to_string_pretty(results).map_err(std::io::Error::other)?;
    std::fs::write(path, json)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn run_one_row_produces_valid_rows_with_energy() {
        // In-process per-circuit check (no subprocess): every circuit proves,
        // verifies, and carries modeled-energy fields.
        for (circuit, k) in [("cubic", 4u32), ("poseidon", POSEIDON_K), ("merkle", MERKLE_K)] {
            let row = run_one_row(circuit, k).expect("row should succeed");
            assert!(row.verified, "{circuit} should verify");
            assert!(row.proof_ms > 0.0);
            assert!(row.assumed_power_w > 0.0);
            assert!(row.proof_energy_j > 0.0);
            assert!(row.proofs_per_joule > 0.0);
        }
    }

    #[test]
    fn assumed_power_env_override_is_respected() {
        // Default when unset.
        std::env::remove_var("ZK_BENCH_POWER_W");
        assert_eq!(assumed_power_w(), DEFAULT_POWER_W);
        // Honored when set to a positive value.
        std::env::set_var("ZK_BENCH_POWER_W", "2.5");
        assert_eq!(assumed_power_w(), 2.5);
        // Ignored when nonsense / non-positive.
        std::env::set_var("ZK_BENCH_POWER_W", "garbage");
        assert_eq!(assumed_power_w(), DEFAULT_POWER_W);
        std::env::remove_var("ZK_BENCH_POWER_W");
    }

    #[test]
    fn bench_row_roundtrips_through_json() {
        // The subprocess path depends on BenchRow surviving JSON round-trip.
        let row = run_one_row("cubic", 4).unwrap();
        let json = serde_json::to_string(&row).unwrap();
        let back: BenchRow = serde_json::from_str(&json).unwrap();
        assert_eq!(back.circuit, "cubic");
        assert_eq!(back.proof_bytes, row.proof_bytes);
        assert!(json.contains("peak_rss_kb"));
        assert!(json.contains("proofs_per_joule"));
    }
}
