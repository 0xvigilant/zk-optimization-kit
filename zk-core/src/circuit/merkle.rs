//! Poseidon Merkle-path membership circuit.
//!
//! Statement proved: "I know a `leaf` and an authentication path (siblings +
//! position bits) such that hashing the leaf up the tree with Poseidon yields the
//! public `root`." In other words: *this leaf is a member of the committed tree*,
//! without revealing which leaf or the path.
//!
//! This is the shape that actually matters for Zcash: spending a note requires
//! proving the note commitment is in the Orchard commitment tree — a Merkle
//! membership proof over an algebraic hash. Zcash's real tree is depth 32 and
//! uses Sinsemilla; here we use a scaled depth-[`MERKLE_DEPTH`] tree over the same
//! Poseidon (`P128Pow5T3`) gadget the rest of the kit uses. It is a *deliberately
//! scaled* analog, not the production circuit — but it exercises the real
//! cost driver (many sequential algebraic hashes), which the toy circuits do not.
//!
//! Per level the running node is combined with its sibling through a constrained
//! conditional swap (driven by the position bit), then fed into the Poseidon hash
//! gadget; the final hash is constrained to the public `root` instance.

use std::convert::TryInto;

use halo2_proofs::{
    circuit::{AssignedCell, Layouter, SimpleFloorPlanner, Value},
    plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Expression, Instance, Selector},
    poly::Rotation,
};
use pasta_curves::Fp;

use halo2_gadgets::poseidon::{
    primitives::{ConstantLength, Hash as PoseidonHash, P128Pow5T3},
    Hash, Pow5Chip, Pow5Config,
};

/// Poseidon spec: standard width-3 / rate-2, same as Orchard and the rest of the kit.
type S = P128Pow5T3;
const WIDTH: usize = 3;
const RATE: usize = 2;
/// Arity-2 Merkle node: each parent hashes exactly two children.
const L: usize = 2;

/// Tree depth (number of hashes on the authentication path). A depth-8 tree holds
/// 256 leaves — a scaled stand-in for Zcash's depth-32 commitment tree.
pub const MERKLE_DEPTH: usize = 8;

/// Smallest `k` that synthesizes a depth-[`MERKLE_DEPTH`] path: the circuit runs
/// [`MERKLE_DEPTH`] sequential Poseidon permutations plus the per-level swap rows.
/// Determined empirically (see tests): `k = 9` is the minimum here.
pub const MERKLE_K: u32 = 9;

/// Off-circuit arity-2 Poseidon hash, identical spec/width/rate to the in-circuit
/// chip — used to compute the expected root for witnesses and tests.
fn hash2(a: Fp, b: Fp) -> Fp {
    PoseidonHash::<_, S, ConstantLength<L>, WIDTH, RATE>::init().hash([a, b])
}

/// Config: the conditional-swap gate columns + selector, the public `root`
/// instance, and the Poseidon chip config.
#[derive(Debug, Clone)]
pub struct MerkleConfig {
    /// Running node coming into a level (copied from the previous level's hash,
    /// or the leaf at level 0).
    cur: Column<Advice>,
    /// The authentication-path sibling at this level.
    sib: Column<Advice>,
    /// Position bit: 0 = current node is the left child, 1 = the right child.
    bit: Column<Advice>,
    /// Left input to this level's hash (after the swap).
    left: Column<Advice>,
    /// Right input to this level's hash (after the swap).
    right: Column<Advice>,
    /// Selector enabling the conditional-swap constraints.
    s_swap: Selector,
    /// Public Merkle root.
    root: Column<Instance>,
    /// Poseidon permutation chip.
    poseidon: Pow5Config<Fp, WIDTH, RATE>,
}

/// Circuit proving Poseidon Merkle membership for a depth-[`MERKLE_DEPTH`] tree.
#[derive(Clone)]
pub struct MerkleCircuit {
    /// The private leaf value.
    pub leaf: Value<Fp>,
    /// The sibling at each level, bottom-up.
    pub siblings: [Value<Fp>; MERKLE_DEPTH],
    /// The position bit at each level (false = current is left child).
    pub positions: [Value<bool>; MERKLE_DEPTH],
}

impl Default for MerkleCircuit {
    fn default() -> Self {
        Self {
            leaf: Value::unknown(),
            siblings: [Value::unknown(); MERKLE_DEPTH],
            positions: [Value::unknown(); MERKLE_DEPTH],
        }
    }
}

impl MerkleCircuit {
    /// Build a circuit with a fixed, known membership witness and return it
    /// together with the correct Merkle root (the public instance value). The
    /// root is computed off-circuit with the same Poseidon primitive.
    pub fn sample() -> (Self, Fp) {
        let leaf = Fp::from(42);
        let mut siblings = [Fp::zero(); MERKLE_DEPTH];
        let mut positions = [false; MERKLE_DEPTH];

        let mut cur = leaf;
        for i in 0..MERKLE_DEPTH {
            let sib = Fp::from((i as u64) + 1);
            let pos = i % 2 == 1; // alternate left/right up the tree
            siblings[i] = sib;
            positions[i] = pos;
            cur = if pos { hash2(sib, cur) } else { hash2(cur, sib) };
        }
        let root = cur;

        let circuit = Self {
            leaf: Value::known(leaf),
            siblings: siblings.map(Value::known),
            positions: positions.map(Value::known),
        };
        (circuit, root)
    }
}

impl Circuit<Fp> for MerkleCircuit {
    type Config = MerkleConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<Fp>) -> MerkleConfig {
        // Conditional-swap columns.
        let cur = meta.advice_column();
        let sib = meta.advice_column();
        let bit = meta.advice_column();
        let left = meta.advice_column();
        let right = meta.advice_column();
        let s_swap = meta.selector();
        let root = meta.instance_column();

        // `cur` is copied in from the previous level's hash output; `left`/`right`
        // are copied into the Poseidon chip. All three need equality.
        meta.enable_equality(cur);
        meta.enable_equality(left);
        meta.enable_equality(right);
        meta.enable_equality(root);

        // Conditional swap: with bit b in {0,1},
        //   left  = cur + b*(sib - cur)   (b=0 -> cur,  b=1 -> sib)
        //   right = sib + b*(cur - sib)   (b=0 -> sib,  b=1 -> cur)
        meta.create_gate("conditional swap", |meta| {
            let s = meta.query_selector(s_swap);
            let cur = meta.query_advice(cur, Rotation::cur());
            let sib = meta.query_advice(sib, Rotation::cur());
            let b = meta.query_advice(bit, Rotation::cur());
            let l = meta.query_advice(left, Rotation::cur());
            let r = meta.query_advice(right, Rotation::cur());
            let one = Expression::Constant(Fp::one());
            vec![
                // b is boolean
                s.clone() * b.clone() * (b.clone() - one),
                // left  = cur + b*(sib - cur)
                s.clone() * (l - (cur.clone() + b.clone() * (sib.clone() - cur.clone()))),
                // right = sib + b*(cur - sib)
                s * (r - (sib.clone() + b * (cur - sib))),
            ]
        });

        // Poseidon chip, configured exactly like the standalone Poseidon circuit.
        let state = (0..WIDTH).map(|_| meta.advice_column()).collect::<Vec<_>>();
        let partial_sbox = meta.advice_column();
        let rc_a = (0..WIDTH).map(|_| meta.fixed_column()).collect::<Vec<_>>();
        let rc_b = (0..WIDTH).map(|_| meta.fixed_column()).collect::<Vec<_>>();
        meta.enable_constant(rc_b[0]);
        let poseidon = Pow5Chip::configure::<S>(
            meta,
            state.try_into().unwrap(),
            partial_sbox,
            rc_a.try_into().unwrap(),
            rc_b.try_into().unwrap(),
        );

        MerkleConfig {
            cur,
            sib,
            bit,
            left,
            right,
            s_swap,
            root,
            poseidon,
        }
    }

    fn synthesize(
        &self,
        config: MerkleConfig,
        mut layouter: impl Layouter<Fp>,
    ) -> Result<(), Error> {
        // Running node, carried up the tree. Starts as the leaf.
        let mut node: Option<AssignedCell<Fp, Fp>> = None;

        for level in 0..MERKLE_DEPTH {
            // --- Conditional swap for this level. ---
            let (l_cell, r_cell) = layouter.assign_region(
                || format!("swap level {level}"),
                |mut region| {
                    config.s_swap.enable(&mut region, 0)?;

                    // cur: leaf at level 0, otherwise copy the previous hash.
                    let cur_cell = match &node {
                        None => region.assign_advice(
                            || "leaf",
                            config.cur,
                            0,
                            || self.leaf,
                        )?,
                        Some(prev) => prev.copy_advice(|| "cur", &mut region, config.cur, 0)?,
                    };

                    let sib_v = self.siblings[level];
                    let pos_v = self.positions[level];
                    region.assign_advice(|| "sib", config.sib, 0, || sib_v)?;
                    region.assign_advice(
                        || "bit",
                        config.bit,
                        0,
                        || pos_v.map(|p| if p { Fp::one() } else { Fp::zero() }),
                    )?;

                    let cur_v = cur_cell.value().copied();
                    let l_v = cur_v
                        .zip(sib_v)
                        .zip(pos_v)
                        .map(|((c, s), p)| if p { s } else { c });
                    let r_v = cur_v
                        .zip(sib_v)
                        .zip(pos_v)
                        .map(|((c, s), p)| if p { c } else { s });

                    let l_cell = region.assign_advice(|| "left", config.left, 0, || l_v)?;
                    let r_cell = region.assign_advice(|| "right", config.right, 0, || r_v)?;
                    Ok((l_cell, r_cell))
                },
            )?;

            // --- Hash the (left, right) pair with Poseidon. ---
            let chip = Pow5Chip::construct(config.poseidon.clone());
            let hasher = Hash::<_, _, S, ConstantLength<L>, WIDTH, RATE>::init(
                chip,
                layouter.namespace(|| format!("poseidon init {level}")),
            )?;
            let digest = hasher.hash(
                layouter.namespace(|| format!("poseidon hash {level}")),
                [l_cell, r_cell],
            )?;
            node = Some(digest);
        }

        // Final node is the Merkle root; constrain it to the public instance.
        let root_cell = node.expect("MERKLE_DEPTH >= 1");
        layouter.constrain_instance(root_cell.cell(), config.root, 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use halo2_proofs::dev::MockProver;

    #[test]
    fn merkle_accepts_valid_path() {
        let (circuit, root) = MerkleCircuit::sample();
        let prover = MockProver::run(MERKLE_K, &circuit, vec![vec![root]]).unwrap();
        assert!(prover.verify().is_ok());
    }

    #[test]
    fn merkle_rejects_wrong_root() {
        let (circuit, root) = MerkleCircuit::sample();
        let wrong = root + Fp::one();
        let prover = MockProver::run(MERKLE_K, &circuit, vec![vec![wrong]]).unwrap();
        assert!(prover.verify().is_err());
    }

    #[test]
    fn merkle_k_minus_one_is_too_small() {
        // Confirms MERKLE_K is the genuine minimum: one k smaller fails to synthesize.
        let (circuit, root) = MerkleCircuit::sample();
        let too_small = MockProver::run(MERKLE_K - 1, &circuit, vec![vec![root]]);
        assert!(
            too_small.is_err(),
            "expected k = {} to be too small for depth {MERKLE_DEPTH}",
            MERKLE_K - 1
        );
    }

    #[test]
    fn merkle_real_prover_roundtrip() {
        let (circuit, root) = MerkleCircuit::sample();
        let run = crate::prover::run_proof(MERKLE_K, &circuit, &[root]).unwrap();
        assert!(run.verified);
    }
}
