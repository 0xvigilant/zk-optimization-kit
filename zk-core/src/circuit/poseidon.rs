//! Poseidon preimage-knowledge circuit.
//!
//! Statement proved: "I know a `preimage` of two field elements such that
//! `Poseidon(preimage) == hash`", with `hash` exposed as the single public
//! instance value.
//!
//! Poseidon is the algebraic hash used in Zcash's Orchard, so this circuit is
//! built directly on `halo2_gadgets`' own Poseidon chip with the standard
//! `P128Pow5T3` specification (width 3 / rate 2). This makes the demo exercise
//! the same Zcash-relevant primitive, not a toy hash.
//!
//! The in-circuit chip and the off-circuit reference hash (used to compute the
//! expected public input) share the exact same spec, width, rate and message
//! length, so the public instance the prover commits to is genuinely the
//! Poseidon digest of the witnessed preimage.

use std::convert::TryInto;
use std::marker::PhantomData;

use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Instance},
};
use pasta_curves::Fp;

use halo2_gadgets::poseidon::{
    primitives::{ConstantLength, P128Pow5T3},
    Hash, Pow5Chip, Pow5Config,
};

/// Poseidon spec used both off-circuit and in-circuit. `P128Pow5T3` is the
/// standard width-3 / rate-2 Poseidon (8 full + 56 partial rounds) — the same
/// one Zcash's Orchard uses.
type S = P128Pow5T3;
/// Permutation state width.
const WIDTH: usize = 3;
/// Sponge rate (number of absorbed elements per permutation).
const RATE: usize = 2;
/// Message length: the preimage is two field elements.
const L: usize = 2;

/// `k` parameter for the proving system (`2^k` rows).
///
/// The `P128Pow5T3` Poseidon chip needs room for its full permutation (8 full +
/// 56 partial rounds across 3 state columns) plus the message-load region. The
/// gadget's own benchmark pins `k = 7`, but empirically `k = 6` is the smallest
/// value that synthesizes here: `k = 6` passes MockProver, while `k = 5` fails
/// with `NotEnoughRowsAvailable { current_k: 5 }`. We therefore pin the minimum,
/// `POSEIDON_K = 6`.
pub const POSEIDON_K: u32 = 6;

/// Per-circuit configuration: the advice columns holding the input message, the
/// public instance column the digest is constrained to, and the Poseidon chip
/// config.
#[derive(Debug, Clone)]
pub struct PoseidonConfig {
    input: [Column<Advice>; L],
    expected: Column<Instance>,
    poseidon: Pow5Config<Fp, WIDTH, RATE>,
}

/// Circuit proving knowledge of a Poseidon preimage.
///
/// Concrete over `Fp` at the public boundary so it can be used exactly like
/// `CubicCircuit` (e.g. by `crate::prover::run_proof` and downstream tasks). The
/// Poseidon spec/width/rate are kept internal as module constants.
#[derive(Clone)]
pub struct PoseidonCircuit {
    /// The private preimage (`L` field elements). `None` for key generation /
    /// `without_witnesses`.
    pub preimage: Value<[Fp; L]>,
    _spec: PhantomData<S>,
}

impl Default for PoseidonCircuit {
    fn default() -> Self {
        Self {
            preimage: Value::unknown(),
            _spec: PhantomData,
        }
    }
}

impl PoseidonCircuit {
    /// Build a circuit with a fixed, known preimage and return it together with
    /// the correct Poseidon digest (the value that must be supplied as the
    /// public instance). The digest is computed with the off-circuit Poseidon
    /// primitive using the same spec/width/rate/length as the in-circuit chip.
    pub fn sample() -> (Self, Fp) {
        let preimage = [Fp::from(1), Fp::from(2)];

        let expected_hash =
            halo2_gadgets::poseidon::primitives::Hash::<_, S, ConstantLength<L>, WIDTH, RATE>::init()
                .hash(preimage);

        let circuit = Self {
            preimage: Value::known(preimage),
            _spec: PhantomData,
        };

        (circuit, expected_hash)
    }
}

impl Circuit<Fp> for PoseidonCircuit {
    type Config = PoseidonConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<Fp>) -> PoseidonConfig {
        // State columns for the permutation, plus the partial-sbox advice column
        // and the two banks of round-constant fixed columns, exactly as the
        // gadget's example configures them.
        let state = (0..WIDTH).map(|_| meta.advice_column()).collect::<Vec<_>>();
        let expected = meta.instance_column();
        meta.enable_equality(expected);
        let partial_sbox = meta.advice_column();

        let rc_a = (0..WIDTH).map(|_| meta.fixed_column()).collect::<Vec<_>>();
        let rc_b = (0..WIDTH).map(|_| meta.fixed_column()).collect::<Vec<_>>();

        meta.enable_constant(rc_b[0]);

        PoseidonConfig {
            input: state[..RATE].try_into().unwrap(),
            expected,
            poseidon: Pow5Chip::configure::<S>(
                meta,
                state.try_into().unwrap(),
                partial_sbox,
                rc_a.try_into().unwrap(),
                rc_b.try_into().unwrap(),
            ),
        }
    }

    fn synthesize(
        &self,
        config: PoseidonConfig,
        mut layouter: impl Layouter<Fp>,
    ) -> Result<(), Error> {
        let chip = Pow5Chip::construct(config.poseidon.clone());

        // Load the message (preimage) into advice cells.
        let message = layouter.assign_region(
            || "load message",
            |mut region| {
                let message_word = |i: usize| {
                    let value = self.preimage.map(|vals| vals[i]);
                    region.assign_advice(
                        || format!("load preimage_{}", i),
                        config.input[i],
                        0,
                        || value,
                    )
                };
                let message: Result<Vec<_>, Error> = (0..L).map(message_word).collect();
                Ok(message?.try_into().unwrap())
            },
        )?;

        // Run the Poseidon hash gadget over the loaded message.
        let hasher = Hash::<_, _, S, ConstantLength<L>, WIDTH, RATE>::init(
            chip,
            layouter.namespace(|| "init"),
        )?;
        let output = hasher.hash(layouter.namespace(|| "hash"), message)?;

        // Constrain the resulting digest to the public instance at row 0.
        layouter.constrain_instance(output.cell(), config.expected, 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ff::Field;
    use halo2_proofs::dev::MockProver;
    use pasta_curves::Fp;

    #[test]
    fn poseidon_accepts_valid_preimage() {
        let (circuit, expected_hash) = PoseidonCircuit::sample();
        let prover = MockProver::run(POSEIDON_K, &circuit, vec![vec![expected_hash]]).unwrap();
        assert!(prover.verify().is_ok());
    }

    #[test]
    fn poseidon_rejects_wrong_hash() {
        let (circuit, expected_hash) = PoseidonCircuit::sample();
        let wrong = expected_hash + Fp::ONE;
        let prover = MockProver::run(POSEIDON_K, &circuit, vec![vec![wrong]]).unwrap();
        assert!(prover.verify().is_err());
    }

    #[test]
    fn poseidon_real_prover_roundtrip() {
        let (circuit, expected_hash) = PoseidonCircuit::sample();
        let run = crate::prover::run_proof(POSEIDON_K, &circuit, &[expected_hash]).unwrap();
        assert!(run.verified);
    }
}
