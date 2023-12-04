pub struct Proof {
    pub index: usize,
    pub value: String,
    pub siblings: Vec<String>,
    pub root: String,
    pub empty: bool,
}

fn _hash(a: &String, b: &String) -> String {
    format!("{}{}", a, b)
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

pub struct MerkleTree {
    data: Vec<String>,        // Stores hash values for all nodes
    leafs: usize,             // Number of leaf nodes
    height: usize,            // Height of the tree
    zero_hashes: Vec<String>, // Stores precomputed hashes of zero nodes at each level
    min_index: usize,         // Minimum index of used leaf nodes
    max_index: usize,         // Maximum index of used leaf nodes
}

impl MerkleTree {
    /// Creates a new Merkle tree with a specified number of levels.
    /// Initializes a tree with 2^n empty leaf nodes.
    pub fn new_with_levels(n: usize) -> MerkleTree {
        // Calculate the number of leaf nodes based on the number of levels
        let leafs = 1 << n; // 2^n leaf nodes

        // Create a vector with empty leaf values
        let leaf_values = vec![String::from("0"); leafs];

        // Call the original new method with the prepared leaf values
        MerkleTree::new(leaf_values)
    }

    /// Creates a new fully computed Merkle tree with given leaf node values.
    pub fn new(leaf_values: Vec<String>) -> MerkleTree {
        let leafs = next_pow2(leaf_values.len());
        let size = 2 * leafs - 1;
        let mut data = vec![String::from("0"); size];

        let mut mt = MerkleTree {
            data,
            leafs,
            height: log2_pow2(size + 1),
            zero_hashes: vec![String::from("0"); log2_pow2(leafs) + 1],
            min_index: usize::MAX,
            max_index: 0,
        };

        mt.compute_zero_hashes();
        for (i, value) in leaf_values.into_iter().enumerate() {
            mt.insert_leaf(i, value);
        }
        mt
    }

    /// Computes the hashes for zero-value nodes at each level of the tree.
    fn compute_zero_hashes(&mut self) {
        let mut current_zero_hash = String::from("0");

        for i in 0..self.zero_hashes.len() {
            self.zero_hashes[i] = _hash(&current_zero_hash, &current_zero_hash);
            current_zero_hash = self.zero_hashes[i].clone();
        }
    }

    /// Recursive helper function for insert_leaf.
    fn insert_leaf_recursive(
        &mut self,
        node_index: usize,
        leaf_index: usize,
        value: String,
        level: usize,
    ) {
        if level == self.height {
            self.data[node_index] = value;
        } else {
            let width = self.leafs >> level;
            let left_index = node_index * 2 + 1;
            let right_index = left_index + 1;

            if leaf_index < width / 2 {
                self.insert_leaf_recursive(left_index, leaf_index, value, level + 1);
            } else {
                self.insert_leaf_recursive(right_index, leaf_index - width / 2, value, level + 1);
            }

            let left_hash = &self.data[left_index];
            let right_hash = if right_index < self.data.len() {
                &self.data[right_index]
            } else {
                &self.zero_hashes[level]
            };
            self.data[node_index] = _hash(left_hash, right_hash);
        }
    }

    /// Inserts a leaf node value and updates the Merkle tree.
    pub fn insert_leaf(&mut self, index: usize, value: String) -> anyhow::Result<()> {
        if index >= self.leafs {
            return Err(anyhow::anyhow!("Index out of bounds"));
        }
        self.min_index = self.min_index.min(index);
        self.max_index = self.max_index.max(index);
        self.insert_leaf_recursive(0, index, value, 0);

        Ok(())
    }

    /// Generates a proof for a leaf node.
    pub fn get_proof(&self, index: usize) -> anyhow::Result<Proof> {
        if index >= self.leafs {
            return Err(anyhow::anyhow!("Index out of bounds"));
        }

        let mut lemma: Vec<String> = Vec::with_capacity(self.height + 1);
        let mut path: Vec<String> = Vec::with_capacity(self.height - 1);

        let mut idx = index;
        let mut base = 0;
        let mut width = self.leafs;

        lemma.push(self.data[idx].clone());
        while base + 1 < self.data.len() {
            let sibling = if idx % 2 == 0 {
                base + idx + 1
            } else {
                base + idx - 1
            };
            path.push(self.data[sibling].clone());

            idx = (base + idx) / 2;
            base += width;
            width /= 2;
        }

        Ok(Proof {
            index,
            value: self.data[index].clone(),
            siblings: path,
            root: self.root(),
            empty: self.data[index] == "0",
        })
    }

    /// Verifies a proof.
    pub fn prove(proof: Proof) -> bool {
        let mut computed_hash = proof.value;
        let mut idx = proof.index;

        for sibling_hash in proof.siblings {
            if idx % 2 == 0 {
                computed_hash = _hash(&computed_hash, &sibling_hash);
            } else {
                computed_hash = _hash(&sibling_hash, &computed_hash);
            }
            idx /= 2;
        }

        computed_hash == proof.root
    }

    /// Returns the Merkle root.
    pub fn root(&self) -> String {
        self.data.last().unwrap().clone()
    }
}
