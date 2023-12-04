use ark_ff::PrimeField;

use crate::hash::HashFunction;

#[derive(Debug)]
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
    data: Vec<F>,        // Stores hash values for all nodes
    leafs: usize,        // Number of leaf nodes
    height: usize,       // Height of the tree
    zero_hashes: Vec<F>, // Stores precomputed hashes of zero nodes at each level
    min_index: usize,    // Minimum index of used leaf nodes
    max_index: usize,    // Maximum index of used leaf nodes
    hash_function: H,    // Hash function instance
}

impl<F: PrimeField, H: HashFunction<F>> MerkleTree<F, H> {
    /// Creates a new Merkle tree with a specified number of levels.
    /// Initializes a tree with 2^n empty leaf nodes.
    pub fn new_with_levels(n: usize, hash_function: H) -> anyhow::Result<MerkleTree<F, H>> {
        // Calculate the number of leaf nodes based on the number of levels
        let leafs = 1 << n; // 2^n leaf nodes

        // Create a vector with empty leaf values
        let leaf_values = vec![hash_function.zero(); leafs];

        // Call the original new method with the prepared leaf values
        MerkleTree::new(leaf_values, hash_function)
    }

    /// Creates a new fully computed Merkle tree with given leaf node values.
    pub fn new(leaf_values: Vec<F>, hash_function: H) -> anyhow::Result<MerkleTree<F, H>> {
        let leafs: usize = next_pow2(leaf_values.len());
        let size: usize = 2 * leafs - 1;
        let data = vec![hash_function.zero(); size];

        let mut mt = MerkleTree {
            data,
            leafs,
            height: log2_pow2(size + 1),
            zero_hashes: vec![hash_function.zero(); log2_pow2(leafs) + 1],
            min_index: usize::MAX,
            max_index: 0,
            hash_function,
        };

        mt.compute_zero_hashes();
        for (i, value) in leaf_values.into_iter().enumerate() {
            mt.insert_leaf(i, value)?;
        }
        Ok(mt)
    }

    /// Computes the hashes for zero-value nodes at each level of the tree.
    fn compute_zero_hashes(&mut self) -> anyhow::Result<()> {
        let mut current_zero_hash = self.hash_function.zero();

        for i in 0..self.zero_hashes.len() {
            self.zero_hashes[i] = self._hash(&current_zero_hash, &current_zero_hash)?;
            current_zero_hash = self.zero_hashes[i].clone();
        }

        Ok(())
    }

    fn insert_leaf_recursive(
        &mut self,
        node_index: usize,
        leaf_index: usize,
        value: F,
        level: usize,
    ) -> anyhow::Result<()> {
        // Check if node_index is within the range of data
        if node_index >= self.data.len() {
            return Ok(());
        }

        if level == self.height - 1 {
            // At a leaf node, set the value
            self.data[node_index] = value;
        } else {
            let half_width = self.leafs >> (level + 1); // Number of nodes on each side at current level
            let left_index = 2 * node_index + 1;
            let right_index = left_index + 1;

            if leaf_index < half_width {
                // Recurse into the left subtree
                self.insert_leaf_recursive(left_index, leaf_index, value, level + 1)?;
            } else {
                // Recurse into the right subtree
                self.insert_leaf_recursive(right_index, leaf_index - half_width, value, level + 1)?;
            }

            let tmpzero = self.hash_function.zero();

            // Update the hash of the parent node
            let left_hash: &F = self.data.get(left_index).unwrap_or(&tmpzero);
            let right_hash = self.data.get(right_index).unwrap_or(&tmpzero);
            self.data[node_index] = self._hash(left_hash, right_hash)?;
        }

        Ok(())
    }

    /// Inserts a leaf node value and updates the Merkle tree.
    pub fn insert_leaf(&mut self, index: usize, value: F) -> anyhow::Result<()> {
        if index >= self.leafs {
            return Err(anyhow::anyhow!("Index out of bounds"));
        }
        self.min_index = self.min_index.min(index);
        self.max_index = self.max_index.max(index);
        self.insert_leaf_recursive(0, index, value, 0)?;

        Ok(())
    }

    /// Generates a proof for a leaf node.
    pub fn get_proof(&self, index: usize) -> anyhow::Result<Proof<F>> {
        if index >= self.leafs {
            return Err(anyhow::anyhow!("Index out of bounds"));
        }

        let mut lemma: Vec<F> = Vec::with_capacity(self.height + 1);
        let mut path: Vec<F> = Vec::with_capacity(self.height - 1);

        let mut idx = index;
        let mut base = 0;
        let mut width = self.leafs;

        lemma.push(self.data[idx].clone());
        while base < self.data.len() {
            let sibling = if idx % 2 == 0 {
                base + idx + 1
            } else {
                base + idx - 1
            };

            if sibling < self.data.len() {
                path.push(self.data[sibling].clone());
            }

            idx = (base + idx) / 2;
            base += width;
            width /= 2;
        }

        Ok(Proof {
            index,
            value: self.data[index].clone(),
            siblings: path,
            root: self.root(),
            empty: self.data[index] == self.hash_function.zero(),
        })
    }

    /// Verifies a proof.
    pub fn prove(&self, proof: Proof<F>) -> anyhow::Result<bool> {
        let mut computed_hash = proof.value;
        let mut idx = proof.index;

        for sibling_hash in proof.siblings {
            if idx % 2 == 0 {
                computed_hash = self._hash(&computed_hash, &sibling_hash)?;
            } else {
                computed_hash = self._hash(&sibling_hash, &computed_hash)?;
            }
            idx /= 2;
        }

        Ok(computed_hash == proof.root)
    }

    /// Returns the Merkle root.
    pub fn root(&self) -> F {
        self.data.last().unwrap().clone()
    }

    fn _hash(&self, a: &F, b: &F) -> anyhow::Result<F> {
        let out = self.hash_function.hash(a, b)?;
        Ok(out[1].clone())
    }
}
