use merkle::{
    hash::poseidon::{PoseidonHash, PoseidonMethod},
    merkle::MerkleTree,
};
use zkhash::poseidon2::poseidon2::Poseidon2;

// Main function for testing
fn main() -> anyhow::Result<()> {
    let n = 12;
    let method = PoseidonMethod::Bn256;
    let hasher = PoseidonMethod::new_bn256()?;
    let hash_function = PoseidonHash::new_for_bintree(method, None, true, None, hasher)?;
    let mut tree = MerkleTree::new_with_levels(n, hash_function)?;

    let proof = tree.get_proof(20)?;
    dbg!(proof);

    Ok(())
}
