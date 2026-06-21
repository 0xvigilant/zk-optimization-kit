//! Real Halo2 proving stack wrapper.
//!
//! This module drives the genuine Halo2 IPA proving pipeline (NOT `MockProver`)
//! over the Pasta curves, so we can produce real proofs and measure setup,
//! proving, and verification timings on edge hardware (e.g. the Orange Pi).
//!
//! The commitment scheme is the **Inner Product Argument (IPA)** over Pasta —
//! Zcash's real, trusted-setup-free stack. In the pinned `halo2_proofs` 0.3.2
//! (the original pasta-only release) the IPA scheme is baked directly into
//! `poly::commitment::Params<C>`; there is no separate `poly::ipa` module and no
//! KZG option. The curve used for the params is `EqAffine` (Vesta), whose
//! scalar field is `Fp` — the field the circuits are defined over.

use std::time::Instant;

use halo2_proofs::{
    plonk::{create_proof, keygen_pk, keygen_vk, verify_proof, Circuit, SingleVerifier},
    poly::commitment::Params,
    transcript::{Blake2bRead, Blake2bWrite, Challenge255},
};
use pasta_curves::{EqAffine, Fp};
use rand::rngs::OsRng;
use serde::Serialize;

/// Result of a single end-to-end proving run: timings, proof size, the
/// verification outcome, and the raw proof bytes.
///
/// Field names are part of the public contract: downstream tasks (benchmark,
/// web server, CLI, standalone verifier) serialize this struct. The `proof`
/// bytes are skipped during JSON serialization but kept in memory so the
/// verifier task can persist them to disk.
#[derive(Serialize, Clone)]
pub struct ProofRun {
    /// Time spent generating the proving/verifying keys (keygen), in ms.
    pub setup_ms: f64,
    /// Time spent creating the proof, in ms.
    pub proof_ms: f64,
    /// Time spent verifying the proof, in ms.
    pub verify_ms: f64,
    /// Size of the serialized proof, in bytes.
    pub proof_bytes: usize,
    /// Whether verification succeeded.
    pub verified: bool,
    /// Raw serialized proof bytes (not included in JSON output).
    #[serde(skip)]
    pub proof: Vec<u8>,
}

/// Run the full IPA proving pipeline for `circuit` with the given `public`
/// instance values, returning timings and the resulting proof.
///
/// `k` is the circuit's domain-size parameter (`2^k` rows). `public` holds the
/// values for the circuit's single instance column (our cubic circuit exports
/// `y` to instance column 0, row 0).
///
/// Generic over `C: Circuit<Fp>` so other circuits (e.g. Task 5's Poseidon)
/// can reuse this proving path.
pub fn run_proof<C: Circuit<Fp> + Clone>(
    k: u32,
    circuit: &C,
    public: &[Fp],
) -> Result<ProofRun, String> {
    // --- Setup: generate the IPA params and keys. ---
    let t0 = Instant::now();
    let params: Params<EqAffine> = Params::new(k);
    let vk = keygen_vk(&params, circuit).map_err(|e| e.to_string())?;
    let pk = keygen_pk(&params, vk.clone(), circuit).map_err(|e| e.to_string())?;
    let setup_ms = t0.elapsed().as_secs_f64() * 1000.0;

    // Instance nesting expected by the API is &[&[&[Fp]]]:
    //   [ per-circuit ][ per-instance-column ][ values ].
    // We prove one circuit with one instance column holding `public`.
    let instances: &[&[&[Fp]]] = &[&[public]];

    // --- Prove. ---
    let t1 = Instant::now();
    let mut transcript = Blake2bWrite::<_, EqAffine, Challenge255<_>>::init(vec![]);
    create_proof(
        &params,
        &pk,
        std::slice::from_ref(circuit),
        instances,
        OsRng,
        &mut transcript,
    )
    .map_err(|e| e.to_string())?;
    let proof = transcript.finalize();
    let proof_ms = t1.elapsed().as_secs_f64() * 1000.0;

    // --- Verify. ---
    let t2 = Instant::now();
    let strategy = SingleVerifier::new(&params);
    let mut vtx = Blake2bRead::<_, EqAffine, Challenge255<_>>::init(&proof[..]);
    let verified = verify_proof(&params, &vk, strategy, instances, &mut vtx).is_ok();
    let verify_ms = t2.elapsed().as_secs_f64() * 1000.0;

    Ok(ProofRun {
        setup_ms,
        proof_ms,
        verify_ms,
        proof_bytes: proof.len(),
        verified,
        proof,
    })
}

/// Verify a previously produced proof against a circuit *shape* and its public
/// instance values, returning `Ok(true)` if the proof is valid.
///
/// This is the single canonical verification entry point: both the CLI `verify`
/// subcommand and the standalone verifier crate call it, so there is exactly one
/// verification code path. The verifying key is rebuilt from the circuit's shape
/// alone (via `keygen_vk` on a `Default` circuit) — no witness is needed, since
/// `configure()` is witness-independent. The verify steps below mirror the
/// verify half of [`run_proof`] exactly: same curve (`EqAffine`), same
/// `Blake2bRead`/`Challenge255` transcript, same `SingleVerifier`, and the same
/// `&[&[public]]` instance nesting.
///
/// `circuit` selects the shape: `"poseidon"` uses the Poseidon circuit, `"merkle"`
/// the Poseidon Merkle-path circuit, and any other value (including the default
/// `"cubic"`) uses the cubic circuit, so unknown names never panic.
pub fn verify_file(circuit: &str, k: u32, proof: &[u8], public: &[Fp]) -> Result<bool, String> {
    use crate::circuit::cubic::CubicCircuit;
    use crate::circuit::merkle::MerkleCircuit;
    use crate::circuit::poseidon::PoseidonCircuit;

    let params: Params<EqAffine> = Params::new(k);
    let vk = match circuit {
        "poseidon" => keygen_vk(&params, &PoseidonCircuit::default()).map_err(|e| e.to_string())?,
        "merkle" => keygen_vk(&params, &MerkleCircuit::default()).map_err(|e| e.to_string())?,
        _ => keygen_vk(&params, &CubicCircuit::default()).map_err(|e| e.to_string())?,
    };

    let strategy = SingleVerifier::new(&params);
    let mut transcript = Blake2bRead::<_, EqAffine, Challenge255<_>>::init(proof);
    Ok(verify_proof(&params, &vk, strategy, &[&[public]], &mut transcript).is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::circuit::cubic::{CubicCircuit, K};
    use pasta_curves::Fp;

    #[test]
    fn verify_file_accepts_valid_cubic_proof() {
        use crate::circuit::cubic::{CubicCircuit, K};
        let circuit = CubicCircuit { x: Some(Fp::from(3)) };
        let run = run_proof(K, &circuit, &[Fp::from(35)]).unwrap();
        assert!(verify_file("cubic", K, &run.proof, &[Fp::from(35)]).unwrap());
        // tampered public must fail
        assert!(!verify_file("cubic", K, &run.proof, &[Fp::from(36)]).unwrap());
    }

    #[test]
    fn prove_and_verify_cubic_roundtrip() {
        let circuit = CubicCircuit { x: Some(Fp::from(3)) };
        let run = run_proof(K, &circuit, &[Fp::from(35)]).unwrap();
        assert!(run.verified);
        assert!(run.proof_bytes > 0);
        assert!(run.proof.len() == run.proof_bytes);
    }
}
