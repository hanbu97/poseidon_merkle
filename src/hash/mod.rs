use ark_ff::PrimeField;
pub mod poseidon;

pub trait HashFunction<F: PrimeField> {
    fn hash(&self, left: &F, right: &F) -> anyhow::Result<Vec<F>>;
    fn zero(&self) -> F;
    fn pad(&self, ileft: &F, right: &F) -> Vec<F>;
}
