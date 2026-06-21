//! Standalone Halo2 proof verifier.
//!
//! Proves to a skeptic that a proof artifact is real and independently checkable
//! WITHOUT the prover: it loads `proof.bin`, the public input, and the circuit
//! name, then calls the single canonical `zk_core::prover::verify_file` (the same
//! verification code path the prover CLI uses — there is no duplicated Halo2
//! verify logic here). Prints `Verified: true|false` and exits 0/1 accordingly.

use clap::Parser;
use pasta_curves::Fp;
use std::process;

use zk_core::circuit::cubic::K;
use zk_core::circuit::poseidon::{PoseidonCircuit, POSEIDON_K};
use zk_core::prover::verify_file;

#[derive(Parser)]
#[command(
    name = "verifier",
    about = "Standalone Halo2 IPA proof verifier (reuses zk_core::prover::verify_file)"
)]
struct Cli {
    /// Circuit shape the proof was produced for: `cubic` or `poseidon`.
    #[arg(long, default_value = "cubic")]
    circuit: String,

    /// Path to the proof file to verify.
    #[arg(long, default_value = "proof.bin")]
    proof: String,

    /// Public input for the `cubic` circuit (the value of y in x^3 + x + 5 = y).
    /// Ignored for `poseidon`: its public input is a 255-bit hash that is not
    /// CLI-typeable, so the known sample digest is used instead.
    #[arg(long, default_value_t = 35)]
    public: u64,
}

fn main() {
    let cli = Cli::parse();

    // Read the proof bytes; never panic on a missing/unreadable file.
    let bytes = match std::fs::read(&cli.proof) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("error: could not read proof file {}: {e}", cli.proof);
            process::exit(1);
        }
    };

    // Select k and the public instance for the chosen circuit shape. For
    // poseidon the CLI cannot accept a 255-bit hash, so we use the known sample
    // digest; for cubic (and any other name) we use the supplied `--public`.
    let (k, public): (u32, Vec<Fp>) = match cli.circuit.as_str() {
        "poseidon" => {
            let (_c, hash) = PoseidonCircuit::sample();
            (POSEIDON_K, vec![hash])
        }
        _ => (K, vec![Fp::from(cli.public)]),
    };

    match verify_file(&cli.circuit, k, &bytes, &public) {
        Ok(true) => {
            println!("Verified: true");
            process::exit(0);
        }
        Ok(false) => {
            println!("Verified: false");
            process::exit(1);
        }
        Err(e) => {
            eprintln!("error: verification failed: {e}");
            println!("Verified: false");
            process::exit(1);
        }
    }
}
