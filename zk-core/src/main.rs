//! `zk-core` command-line interface — the user-facing driver for the demo on the
//! Pi (and any host). Four subcommands wrap the real Halo2 IPA stack:
//!
//!   - `prove`  — run a genuine proof for a circuit, write `./proof.bin`, print JSON.
//!   - `bench`  — run the full (circuit, k) sweep, persist JSON, print a table.
//!   - `serve`  — warm up one proof then launch the dashboard web server.
//!   - `verify` — verify `./proof.bin` via the single canonical `prover::verify_file`.
//!
//! There is exactly ONE verification code path: this CLI's `verify` subcommand
//! and the standalone verifier crate both call [`zk_core::prover::verify_file`].

use std::net::SocketAddr;

use clap::{Parser, Subcommand};
use pasta_curves::Fp;

use zk_core::bench::{prove_named, run_bench, run_one_row, write_json};
use zk_core::circuit::cubic::K;
use zk_core::circuit::merkle::{MerkleCircuit, MERKLE_K};
use zk_core::circuit::poseidon::{PoseidonCircuit, POSEIDON_K};
use zk_core::prover;
use zk_core::server;

/// Canonical on-disk path for the proof artifact, shared with the dashboard and
/// the standalone verifier.
const PROOF_PATH: &str = "./proof.bin";

#[derive(Parser)]
#[command(
    name = "zk-core",
    about = "Halo2 IPA zk-prover for edge hardware (prove / bench / serve / verify)"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run a real proof for a circuit, write ./proof.bin, and print the run as JSON.
    Prove {
        /// Circuit to prove: `cubic` (x^3+x+5=35), `poseidon`, or `merkle`.
        #[arg(long, default_value = "cubic")]
        circuit: String,
        /// Domain size `k` (`2^k` rows). Defaults to the circuit's minimum. Larger
        /// values size up the domain — used to probe the hardware's memory/time
        /// wall (see the README "scaling" section).
        #[arg(long)]
        k: Option<u32>,
    },
    /// Run the full benchmark sweep, write bench-results/results.json, print a table.
    Bench,
    /// Internal: prove one (circuit, k) point in an isolated process and print its
    /// single benchmark row as JSON. Used by `bench` to get per-row peak memory.
    BenchOne {
        /// Circuit to prove: `cubic`, `poseidon`, or `merkle`.
        #[arg(long, default_value = "cubic")]
        circuit: String,
        /// Domain size `k` (`2^k` rows).
        #[arg(long)]
        k: u32,
    },
    /// Run one proof for the dashboard, then serve the live web demo.
    Serve {
        /// TCP port to listen on.
        #[arg(long, default_value_t = 8080)]
        port: u16,
    },
    /// Verify a proof file via the canonical verification path.
    Verify {
        /// Circuit shape the proof was produced for: `cubic` or `poseidon`.
        #[arg(long, default_value = "cubic")]
        circuit: String,
        /// Path to the proof file to verify.
        #[arg(long, default_value = PROOF_PATH)]
        proof: String,
        /// Public input for `cubic` (the value `y` in x^3+x+5=y). Ignored for
        /// `poseidon`: a 255-bit hash isn't typeable on the CLI, so the known
        /// `PoseidonCircuit::sample()` digest is used instead.
        #[arg(long, default_value_t = 35)]
        public: u64,
    },
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    match cli.command {
        Command::Prove { circuit, k } => cmd_prove(&circuit, k),
        Command::Bench => cmd_bench(),
        Command::BenchOne { circuit, k } => cmd_bench_one(&circuit, k),
        Command::Serve { port } => cmd_serve(port).await,
        Command::Verify {
            circuit,
            proof,
            public,
        } => cmd_verify(&circuit, &proof, public),
    }
}

/// Canonical minimum `k` for a circuit, used when `prove --k` is omitted.
fn default_k(circuit: &str) -> u32 {
    match circuit {
        "poseidon" => POSEIDON_K,
        "merkle" => MERKLE_K,
        _ => K,
    }
}

/// `prove`: build the circuit, run a real proof, persist `./proof.bin`, print JSON.
/// Unknown circuit names fall back to cubic (never panics on user input). `k`
/// defaults to the circuit's minimum but can be raised to probe the hardware wall.
fn cmd_prove(circuit: &str, k: Option<u32>) {
    let k = k.unwrap_or_else(|| default_k(circuit));
    let run = prove_named(circuit, k);

    match run {
        Ok(run) => {
            if let Err(e) = std::fs::write(PROOF_PATH, &run.proof) {
                eprintln!("error: could not write {PROOF_PATH}: {e}");
                std::process::exit(1);
            }
            match serde_json::to_string_pretty(&run) {
                Ok(json) => println!("{json}"),
                Err(e) => {
                    eprintln!("error: could not serialize proof run: {e}");
                    std::process::exit(1);
                }
            }
        }
        Err(e) => {
            eprintln!("error: proof failed: {e}");
            std::process::exit(1);
        }
    }
}

/// `bench`: run the sweep, persist JSON (creating its parent dir), print a table.
fn cmd_bench() {
    let results = run_bench();

    if let Err(e) = std::fs::create_dir_all("bench-results") {
        eprintln!("error: could not create bench-results/: {e}");
        std::process::exit(1);
    }
    let path = "bench-results/results.json";
    if let Err(e) = write_json(&results, path) {
        eprintln!("error: could not write {path}: {e}");
        std::process::exit(1);
    }

    // Human-readable table.
    println!(
        "{:<9} {:>3} {:>10} {:>10} {:>10} {:>11} {:>12} {:>9} {:>10} {:>8}",
        "circuit",
        "k",
        "setup_ms",
        "proof_ms",
        "verify_ms",
        "proof_bytes",
        "peak_rss_kb",
        "energy_J",
        "proofs/J",
        "verified"
    );
    for r in &results.rows {
        println!(
            "{:<9} {:>3} {:>10.2} {:>10.2} {:>10.2} {:>11} {:>12} {:>9.3} {:>10.2} {:>8}",
            r.circuit,
            r.k,
            r.setup_ms,
            r.proof_ms,
            r.verify_ms,
            r.proof_bytes,
            r.peak_rss_kb,
            r.proof_energy_j,
            r.proofs_per_joule,
            r.verified
        );
    }
    if let Some(r) = results.rows.first() {
        println!(
            "\nenergy is MODELED at {:.2} W (set ZK_BENCH_POWER_W to your measured wattage)",
            r.assumed_power_w
        );
    }
    println!("JSON written to {path}");
}

/// `bench-one`: run exactly one (circuit, k) point in this (fresh) process and
/// print its single benchmark row as JSON. The isolated process is what gives
/// `peak_rss_kb` a genuine per-row meaning; `bench` spawns this per sweep point.
fn cmd_bench_one(circuit: &str, k: u32) {
    match run_one_row(circuit, k) {
        Ok(row) => match serde_json::to_string(&row) {
            Ok(json) => println!("{json}"),
            Err(e) => {
                eprintln!("error: could not serialize bench row: {e}");
                std::process::exit(1);
            }
        },
        Err(e) => {
            eprintln!("error: bench-one {circuit} k={k} failed: {e}");
            std::process::exit(1);
        }
    }
}

/// `serve`: warm up one proof (so the dashboard has data) then launch the server.
async fn cmd_serve(port: u16) {
    // Produce an initial real proof so the dashboard shows data immediately;
    // this also writes ./proof.bin.
    let _ = server::run_prove_circuit("cubic").await;

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    println!("Listening on http://{addr}");
    if let Err(e) = server::serve(addr).await {
        eprintln!("error: server failed: {e}");
        std::process::exit(1);
    }
}

/// `verify`: read the proof bytes and verify them via the single canonical path.
/// Exits 0 if valid, 1 if invalid or on any error (never panics on user input).
fn cmd_verify(circuit: &str, proof_path: &str, public: u64) {
    let proof = match std::fs::read(proof_path) {
        Ok(bytes) => bytes,
        Err(e) => {
            eprintln!("error: could not read proof file {proof_path}: {e}");
            std::process::exit(1);
        }
    };

    // Select k and the public instance for the chosen circuit shape. For
    // poseidon, the CLI cannot accept a 255-bit hash, so we use the known
    // sample digest; for cubic (and any unknown name) we use the supplied value.
    let (k, public_inputs) = match circuit {
        "poseidon" => {
            let (_c, hash) = PoseidonCircuit::sample();
            (POSEIDON_K, vec![hash])
        }
        "merkle" => {
            let (_c, root) = MerkleCircuit::sample();
            (MERKLE_K, vec![root])
        }
        _ => (K, vec![Fp::from(public)]),
    };

    match prover::verify_file(circuit, k, &proof, &public_inputs) {
        Ok(true) => {
            println!("Verified: true");
            std::process::exit(0);
        }
        Ok(false) => {
            println!("Verified: false");
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("error: verification failed: {e}");
            std::process::exit(1);
        }
    }
}
