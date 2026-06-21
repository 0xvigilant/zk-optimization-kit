//! Integration regression guard for the standalone verifier path.
//!
//! Produces a real cubic proof via `zk_core::prover::run_proof`, persists it to a
//! temp file (mirroring how the CLI writes `proof.bin`), reads it back, and runs
//! the single canonical `zk_core::prover::verify_file` — the exact function the
//! `verifier` binary calls. Asserts a valid proof verifies and that a tampered
//! public input is rejected.

use pasta_curves::Fp;
use zk_core::circuit::cubic::{CubicCircuit, K};
use zk_core::prover::{run_proof, verify_file};

#[test]
fn verifier_accepts_valid_cubic_proof_and_rejects_tampered_public() {
    // 1. Produce a real cubic proof of x = 3, y = 35 (3^3 + 3 + 5 = 35).
    let circuit = CubicCircuit { x: Some(Fp::from(3)) };
    let run = run_proof(K, &circuit, &[Fp::from(35)]).expect("proving should succeed");

    // 2. Write the proof bytes to a temp path (as the CLI does for proof.bin).
    let mut path = std::env::temp_dir();
    path.push(format!("verifier_sample_proof_{}.bin", std::process::id()));
    std::fs::write(&path, &run.proof).expect("writing proof should succeed");

    // 3. Read them back and verify via the canonical path -> Ok(true).
    let bytes = std::fs::read(&path).expect("reading proof should succeed");
    let ok = verify_file("cubic", K, &bytes, &[Fp::from(35)]).expect("verify should not error");
    assert!(ok, "valid cubic proof must verify");

    // 4. A tampered public input must be rejected -> Ok(false).
    let bad = verify_file("cubic", K, &bytes, &[Fp::from(36)]).expect("verify should not error");
    assert!(!bad, "tampered public input must be rejected");

    let _ = std::fs::remove_file(&path);
}
