use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Expression, Instance, Selector},
    poly::Rotation,
};
use pasta_curves::Fp;

/// `k` parameter for the proving system: the circuit uses 2^K rows. The cubic
/// circuit only needs a handful of rows, so a small domain suffices.
pub const K: u32 = 4;

#[derive(Clone, Debug)]
pub struct CubicConfig {
    /// private input `x`
    x: Column<Advice>,
    /// intermediate `x^2`
    x2: Column<Advice>,
    /// intermediate `x^3`
    x3: Column<Advice>,
    /// output `out = x^3 + x + 5`, exported to the instance column
    out: Column<Advice>,
    /// public output `y`
    y: Column<Instance>,
    /// selector toggling the cubic gate
    s: Selector,
}

#[derive(Default, Clone)]
pub struct CubicCircuit {
    pub x: Option<Fp>,
}

impl Circuit<Fp> for CubicCircuit {
    type Config = CubicConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self { x: None }
    }

    fn configure(meta: &mut ConstraintSystem<Fp>) -> CubicConfig {
        let x = meta.advice_column();
        let x2 = meta.advice_column();
        let x3 = meta.advice_column();
        let out = meta.advice_column();
        let y = meta.instance_column();
        let s = meta.selector();

        // `out` must be equality-constrainable so it can be wired to the
        // instance column `y`.
        meta.enable_equality(out);
        meta.enable_equality(y);

        meta.create_gate("x^3 + x + 5 = y", |meta| {
            let s = meta.query_selector(s);
            let x = meta.query_advice(x, Rotation::cur());
            let x2 = meta.query_advice(x2, Rotation::cur());
            let x3 = meta.query_advice(x3, Rotation::cur());
            let out = meta.query_advice(out, Rotation::cur());
            let five = Expression::Constant(Fp::from(5));
            vec![
                // x2 = x * x
                s.clone() * (x2.clone() - x.clone() * x.clone()),
                // x3 = x2 * x
                s.clone() * (x3.clone() - x2 * x.clone()),
                // out = x3 + x + 5
                s * (out - x3 - x - five),
            ]
        });

        CubicConfig {
            x,
            x2,
            x3,
            out,
            y,
            s,
        }
    }

    fn synthesize(
        &self,
        config: CubicConfig,
        mut layouter: impl Layouter<Fp>,
    ) -> Result<(), Error> {
        let out_cell = layouter.assign_region(
            || "cubic",
            |mut region| {
                // Activate the gate on row 0.
                config.s.enable(&mut region, 0)?;

                let x_val = self.x.map(Value::known).unwrap_or_else(Value::unknown);

                // Assign x.
                region.assign_advice(|| "x", config.x, 0, || x_val)?;

                // x2 = x * x
                let x2_val = x_val * x_val;
                region.assign_advice(|| "x2", config.x2, 0, || x2_val)?;

                // x3 = x2 * x
                let x3_val = x2_val * x_val;
                region.assign_advice(|| "x3", config.x3, 0, || x3_val)?;

                // out = x3 + x + 5
                let out_val = x3_val + x_val + Value::known(Fp::from(5));
                let out_cell =
                    region.assign_advice(|| "out", config.out, 0, || out_val)?;

                Ok(out_cell)
            },
        )?;

        // Wire `out` to the public instance `y` at row 0.
        layouter.constrain_instance(out_cell.cell(), config.y, 0)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use halo2_proofs::dev::MockProver;
    use pasta_curves::Fp;

    #[test]
    fn cubic_accepts_valid_witness() {
        // x = 3 -> y = 27 + 3 + 5 = 35
        let circuit = CubicCircuit { x: Some(Fp::from(3)) };
        let public = vec![Fp::from(35)];
        let prover = MockProver::run(K, &circuit, vec![public]).unwrap();
        assert!(prover.verify().is_ok());
    }

    #[test]
    fn cubic_rejects_wrong_public() {
        let circuit = CubicCircuit { x: Some(Fp::from(3)) };
        let public = vec![Fp::from(36)]; // wrong y
        let prover = MockProver::run(K, &circuit, vec![public]).unwrap();
        assert!(prover.verify().is_err());
    }
}
