use ark_ff::PrimeField;

pub trait HashFunction {
    fn hash<F: PrimeField>(&self, left: &[F], right: &[F]) -> anyhow::Result<F>;
}

pub mod poseidon;
