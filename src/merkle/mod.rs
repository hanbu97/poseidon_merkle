use ark_ff::PrimeField;

use crate::hash::HashFunction;

#[derive(Debug, Clone)]
pub struct Proof<F: PrimeField> {
    pub index: usize,
    pub value: F,
    pub siblings: Vec<F>,
    pub root: F,
    pub empty: bool,
}

/// Returns the next power of two for a given number if it is not already a power of two.
pub fn next_pow2(mut n: usize) -> usize {
    n -= 1;
    n |= n >> 1;
    n |= n >> 2;
    n |= n >> 4;
    n |= n >> 8;
    n |= n >> 16;
    #[cfg(target_pointer_width = "64")]
    {
        n |= n >> 32;
    }
    n + 1
}

/// Finds the power of 2 logarithm of a number that is itself a power of 2.
pub fn log2_pow2(n: usize) -> usize {
    n.trailing_zeros() as usize
}

pub struct MerkleTree<F: PrimeField, H: HashFunction<F>> {
    pub data: Vec<F>,  // Stores hash values for all nodes
    leafs: usize,      // Number of leaf nodes
    pub height: usize, // Height of the tree
    #[allow(dead_code)]
    zero_hashes: Vec<F>, // Stores precomputed hashes of zero nodes at each level
    #[allow(dead_code)]
    min_index: usize, // Minimum index of used leaf nodes
    #[allow(dead_code)]
    max_index: usize, // Maximum index of used leaf nodes
    hash_function: H,  // Hash function instance
}

impl<F: PrimeField, H: HashFunction<F>> MerkleTree<F, H> {
    /// Creates a new Merkle tree with a specified number of levels.
    /// Initializes a tree with 2^n empty leaf nodes.
    pub fn new_with_levels(n: usize, hash_function: H) -> anyhow::Result<MerkleTree<F, H>> {
        // Calculate the number of leaf nodes based on the number of levels
        let leafs = 1 << (n - 1); // 2^n leaf nodes
                                  // Create a vector with empty leaf values
        let leaf_values = vec![hash_function.zero(); leafs];

        // Call the original new method with the prepared leaf values
        MerkleTree::new(leaf_values, hash_function)
    }

    /// Creates a new fully computed Merkle tree with given leaf node values.
    pub fn new(leaf_values: Vec<F>, hash_function: H) -> anyhow::Result<MerkleTree<F, H>> {
        let leafs: usize = next_pow2(leaf_values.len());
        let size: usize = 2 * leafs - 1;
        let height: usize = log2_pow2(leafs);

        // compute zeros
        let mut current_zero_hash = hash_function.zero();
        let mut zero_hashes = Vec::with_capacity(height);
        for _ in 0..height {
            zero_hashes.push(current_zero_hash);
            current_zero_hash = hash_function.hash(&current_zero_hash, &current_zero_hash)?[1];
        }

        // calculate merkle tree
        let mut data = leaf_values.clone();
        data.resize(size, hash_function.zero());

        let mut current_level = 0;
        let mut current_level_size = leafs;
        let mut level_leafs_accumulated = 0;

        while current_level < height {
            let mut i = 0;
            while i < current_level_size {
                let left_index = level_leafs_accumulated + i;
                let right_index = left_index + 1;

                let left = data[left_index];
                let right = data[right_index];

                data[level_leafs_accumulated + current_level_size + i / 2] =
                    hash_function.hash(&left, &right)?[1];
                i += 2;
            }

            level_leafs_accumulated += current_level_size;
            current_level_size /= 2;
            current_level += 1;
        }

        let mt = MerkleTree {
            data,
            leafs,
            height,
            zero_hashes,
            min_index: usize::MAX,
            max_index: 0,
            hash_function,
        };

        Ok(mt)
    }

    /// computes siblings and parent nodes index
    pub fn compute_indices(&self, index: usize) -> (Vec<usize>, Vec<usize>) {
        let mut level = 0;
        let mut level_leafs = self.leafs;
        let mut level_leafs_accumulated = 0;

        let mut siblings = vec![];
        let mut parents = vec![];
        let mut index = index;

        while level < self.height {
            let sibling_index = if index % 2 == 0 { index + 1 } else { index - 1 };
            siblings.push(sibling_index + level_leafs_accumulated);

            level_leafs_accumulated += level_leafs;
            level_leafs /= 2;
            let parent_index = index / 2;
            index = parent_index;
            parents.push(parent_index + level_leafs_accumulated);

            level += 1;
        }

        (siblings, parents)
    }

    pub fn insert_leaf(&mut self, index: usize, value: F) -> anyhow::Result<()> {
        if index >= self.leafs {
            return Err(anyhow::anyhow!("Index out of bounds"));
        }

        self.data[index] = value;
        let (siblings, parents) = self.compute_indices(index);

        let mut value = value;
        for (sib_idx, par_idx) in siblings.iter().zip(parents.iter()) {
            let sibling_index = *sib_idx;
            let parent_index = *par_idx;

            let sibling = self.data[sibling_index];
            value = if sibling_index % 2 == 0 {
                self._hash(&sibling, &value)?
            } else {
                self._hash(&value, &sibling)?
            };

            self.data[parent_index] = value;
        }

        Ok(())
    }

    /// Generates a proof for a leaf node.
    pub fn get_proof(&self, index: usize) -> anyhow::Result<Proof<F>> {
        if index >= self.leafs {
            return Err(anyhow::anyhow!("Index out of bounds")); // Check if the index is within the bounds
        }

        let leaf_value = self.data[index]; // Clone the leaf value
        let (siblings, _) = self.compute_indices(index);

        let path: Vec<F> = siblings
            .iter()
            .map(|sibling_index| self.data[*sibling_index])
            .collect();
        let root_value = self.root(); // Clone the root value

        Ok(Proof {
            index,
            value: leaf_value,
            siblings: path,
            root: root_value,
            empty: leaf_value == self.hash_function.zero(), // Check if the leaf value is the same as zero value
        })
    }

    /// Verifies a proof.
    pub fn prove(&self, proof: Proof<F>) -> anyhow::Result<bool> {
        let mut computed_hash = proof.value;
        let (siblings, _) = self.compute_indices(proof.index);

        for (sibidx, sib) in siblings.into_iter().enumerate() {
            if sib % 2 == 0 {
                computed_hash = self._hash(&proof.siblings[sibidx], &computed_hash)?;
            } else {
                computed_hash = self._hash(&computed_hash, &proof.siblings[sibidx])?;
            }
        }

        Ok(computed_hash == proof.root
            && proof.root == self.root()
            && proof.siblings.len() == self.height)
    }

    /// Returns the Merkle root.
    pub fn root(&self) -> F {
        *self.data.last().unwrap()
    }

    fn _hash(&self, a: &F, b: &F) -> anyhow::Result<F> {
        let out = self.hash_function.hash(a, b)?;
        Ok(out[1])
    }
}
