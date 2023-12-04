use ark_ff::PrimeField;

pub trait HashFunction<F: PrimeField> {
    fn hash(&self, left: &[F], right: &[F]) -> anyhow::Result<F>;
}

pub mod poseidon;
