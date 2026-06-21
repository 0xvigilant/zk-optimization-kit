//! Axum web server + terminal-style dashboard for the edge prover.
//!
//! Serves a self-contained green-on-black "hacker terminal" page that polls live
//! hardware stats and lets the user trigger a real Halo2 proof on demand,
//! displaying setup/proof/verify timings, proof size, and verification status.
//!
//! This is THE visual demo for the grant: every proof shown is a genuine IPA
//! proof produced by `prover::run_proof` on the device. The canonical proof
//! artifact is written to `./proof.bin` so the CLI and standalone verifier in
//! later tasks can pick it up.

use std::collections::HashMap;
use std::net::SocketAddr;

use axum::{
    extract::Query,
    http::{header, StatusCode},
    response::{Html, IntoResponse},
    routing::{get, post},
    Json, Router,
};
use pasta_curves::Fp;

use crate::circuit::cubic::{CubicCircuit, K};
use crate::circuit::merkle::{MerkleCircuit, MERKLE_K};
use crate::circuit::poseidon::{PoseidonCircuit, POSEIDON_K};
use crate::hwinfo::HwInfo;
use crate::prover::{run_proof, ProofRun};

/// Canonical on-disk path for the most recent proof artifact, shared with the
/// CLI and the standalone verifier.
const PROOF_PATH: &str = "./proof.bin";

/// Run a real proof for the named circuit and return the result.
///
/// Dispatch:
///   - `"cubic"`    → the `x^3 + x + 5 = 35` circuit (witness `x = 3`).
///   - `"poseidon"` → a sampled Poseidon hash circuit.
///   - `"merkle"`   → a sampled Poseidon Merkle-path membership circuit.
///   - anything else → defaults to `"cubic"` (never panics on unknown input).
///
/// On a successful run the raw proof bytes are written to [`PROOF_PATH`] on a
/// best-effort basis: write errors (e.g. a read-only cwd) are ignored so the
/// server keeps working.
///
/// `run_proof` is synchronous and CPU-bound; for this demo a direct call inside
/// the async fn is acceptable.
pub async fn run_prove_circuit(name: &str) -> ProofRun {
    let result = match name {
        "poseidon" => {
            let (circuit, hash) = PoseidonCircuit::sample();
            run_proof(POSEIDON_K, &circuit, &[hash])
        }
        "merkle" => {
            let (circuit, root) = MerkleCircuit::sample();
            run_proof(MERKLE_K, &circuit, &[root])
        }
        // "cubic" and any unknown name fall back to the cubic circuit.
        _ => {
            let circuit = CubicCircuit { x: Some(Fp::from(3)) };
            run_proof(K, &circuit, &[Fp::from(35)])
        }
    };

    match result {
        Ok(run) => {
            // Best-effort persist; ignore failures so a read-only cwd can't crash us.
            let _ = std::fs::write(PROOF_PATH, &run.proof);
            run
        }
        // A proving failure shouldn't take down the handler. Surface it as an
        // unverified, zero-timing run so the dashboard can render "✗".
        Err(_) => ProofRun {
            setup_ms: 0.0,
            proof_ms: 0.0,
            verify_ms: 0.0,
            proof_bytes: 0,
            verified: false,
            proof: Vec::new(),
        },
    }
}

/// `GET /` — serve the dashboard. The HTML is compiled into the binary so the
/// server is a single self-contained artifact (no asset directory needed at
/// runtime, important for deploying to a bare Pi).
async fn index() -> impl IntoResponse {
    Html(include_str!("../static/index.html"))
}

/// `GET /api/hwinfo` — live hardware stats as JSON.
async fn hwinfo() -> impl IntoResponse {
    Json(HwInfo::collect())
}

/// `POST /api/prove?circuit=cubic|poseidon` — run a real proof and return its
/// timings/size/verification as JSON. Defaults to "cubic" when the param is
/// absent or unknown.
async fn prove(Query(params): Query<HashMap<String, String>>) -> impl IntoResponse {
    let circuit = params.get("circuit").map(String::as_str).unwrap_or("cubic");
    let run = run_prove_circuit(circuit).await;
    Json(run)
}

/// `GET /api/proof` — download the most recent proof artifact as a binary file.
/// Returns 404 if no proof has been produced yet.
async fn proof_download() -> impl IntoResponse {
    match std::fs::read(PROOF_PATH) {
        Ok(bytes) => (
            StatusCode::OK,
            [
                (header::CONTENT_TYPE, "application/octet-stream"),
                (
                    header::CONTENT_DISPOSITION,
                    "attachment; filename=\"proof.bin\"",
                ),
            ],
            bytes,
        )
            .into_response(),
        Err(_) => (StatusCode::NOT_FOUND, "no proof available").into_response(),
    }
}

/// Build the application router with all routes wired up.
pub fn app() -> Router {
    Router::new()
        .route("/", get(index))
        .route("/api/hwinfo", get(hwinfo))
        .route("/api/prove", post(prove))
        .route("/api/proof", get(proof_download))
}

/// Bind to `addr` and serve the dashboard until the process is stopped.
/// Returns `Err` on bind/serve failure instead of panicking.
pub async fn serve(addr: SocketAddr) -> Result<(), String> {
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .map_err(|e| format!("failed to bind {addr}: {e}"))?;
    axum::serve(listener, app())
        .await
        .map_err(|e| format!("server error: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn prove_handler_returns_verified_json() {
        let body = run_prove_circuit("cubic").await;
        assert!(body.verified);
    }
    #[tokio::test]
    async fn unknown_circuit_does_not_panic() {
        let _ = run_prove_circuit("bogus").await;
    }
}
