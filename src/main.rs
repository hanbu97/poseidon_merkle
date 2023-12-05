use merkle::{
    hash::poseidon::{PoseidonHash, PoseidonMethod},
    merkle::MerkleTree,
};
use zkhash::{fields::bn256::FpBN256, poseidon2::poseidon2::Poseidon2};

// Main function for testing
fn main() -> anyhow::Result<()> {
    let n = 4;

    let method = PoseidonMethod::Bn256;
    let hasher: Poseidon2<ark_ff::Fp<ark_ff::MontBackend<zkhash::fields::bn256::FqConfig, 4>, 4>> =
        PoseidonMethod::new_bn256()?;
    let hash_function = PoseidonHash::new_for_bintree(method, None, true, None, hasher)?;
    let mut tree = MerkleTree::new_with_levels(n, hash_function)?;

    tree.insert_leaf(0, FpBN256::from(123u64))?;

    let proof = tree.get_proof(1)?;
    dbg!(&proof);

    dbg!(tree.prove(proof.clone())?);
    tree.insert_leaf(1, FpBN256::from(123u64))?;
    dbg!(tree.prove(proof.clone())?);

    tree.insert_leaf(1, FpBN256::from(0u64))?;
    dbg!(tree.prove(proof.clone())?);

    let mut proof = tree.get_proof(0)?;
    proof.value = FpBN256::from(124u64);

    dbg!(tree.prove(proof.clone())?);
    proof.value = FpBN256::from(123u64);
    proof.index = 1;
    dbg!(tree.prove(proof.clone())?);

    proof.index = 0;
    dbg!(tree.prove(proof.clone())?);

    Ok(())
}
