use std::collections::HashMap;
use zkhash::{
    fields::bn256::FpBN256,
    gmimc::{gmimc::Gmimc, gmimc_instance_bn256::GMIMC_BN_3_PARAMS},
    poseidon::{poseidon::Poseidon, poseidon_instance_bn256::POSEIDON_BN_PARAMS},
    poseidon2::{poseidon2::Poseidon2, poseidon2_instance_bn256::POSEIDON2_BN256_PARAMS},
};
// use zkhash::{Fr, Poseidon};

// A simplified hash function (for demonstration purposes)
fn hash(data: &str) -> String {
    // format!("{:x}", md5::compute(data))
    "hash".to_string()
}

// The Merkle Tree structure
struct MerkleTree {
    leaves: HashMap<usize, String>,  // Stores the leaf nodes
    nodes: HashMap<usize, String>,   // Stores all nodes (including leaf and internal nodes)
    level_empty_hashes: Vec<String>, // Precomputed hashes for empty nodes at each level
    depth: usize,                    // Depth of the tree
}

// The structure representing a proof for a leaf node
#[derive(Debug, Clone)]
struct Proof {
    index: usize,          // Index of the leaf node
    value: String,         // Value of the node (hash)fff
    siblings: Vec<String>, // Hashes of sibling nodes along the path to the root
    root: String,          // Hash of the root node
    empty: bool,           // Indicator whether the node is empty
}

impl MerkleTree {
    // Constructor for MerkleTree
    fn new(depth: usize) -> Self {
        let mut level_empty_hashes = vec!["".to_string(); depth + 1];

        // Precompute the empty hash for each level
        for i in (0..depth).rev() {
            let hash = if i == depth - 1 {
                hash("") // The empty hash at the leaf level
            } else {
                hash(&(level_empty_hashes[i + 1].clone() + &level_empty_hashes[i + 1]))
            };
            level_empty_hashes[i] = hash;
        }

        MerkleTree {
            leaves: HashMap::new(),
            nodes: HashMap::new(),
            level_empty_hashes,
            depth,
        }
    }

    // Inserts or updates a leaf node and updates the tree
    fn insert_leaf(&mut self, index: usize, value: String) {
        let hash_value = hash(&value);
        self.leaves.insert(index, hash_value.clone());
        self.nodes.insert(index, hash_value);

        // Update the tree path from the leaf to the root
        let mut current_index = index;
        let mut current_level = self.depth;
        while current_index > 0 {
            current_index = parent_index(current_index);
            current_level -= 1;
            self.update_node(current_index, current_level);
        }
    }

    // Updates a node hash based on its children
    fn update_node(&mut self, index: usize, level: usize) {
        let left_child_index = left_child_index(index);
        let right_child_index = right_child_index(index);

        let left_child_hash = self
            .nodes
            .get(&left_child_index)
            .unwrap_or(&self.level_empty_hashes[level + 1]);
        let right_child_hash = self
            .nodes
            .get(&right_child_index)
            .unwrap_or(&self.level_empty_hashes[level + 1]);

        let new_hash = hash(&(left_child_hash.clone() + &right_child_hash.clone()));
        self.nodes.insert(index, new_hash);
    }

    // Generates a proof for the specified leaf node
    fn get_proof(&self, index: usize) -> Option<Proof> {
        if !self.leaves.contains_key(&index) {
            return None;
        }

        let mut proof = Proof {
            index,
            value: self.leaves.get(&index).cloned().unwrap_or_default(),
            siblings: Vec::new(),
            root: self.nodes.get(&0).cloned().unwrap_or_default(),
            empty: false,
        };

        let mut current_index = index;
        let mut current_level = self.depth;
        while current_index > 0 {
            let sibling_index = sibling_index(current_index);
            let sibling_hash = self
                .nodes
                .get(&sibling_index)
                .unwrap_or(&self.level_empty_hashes[current_level])
                .clone();
            proof.siblings.push(sibling_hash);
            current_index = parent_index(current_index);
            current_level -= 1;
        }

        Some(proof)
    }

    // Verifies a proof for a leaf node
    fn prove(&self, proof: Proof) -> bool {
        let mut current_hash = hash(&proof.value);
        let mut current_index = proof.index;

        for (i, sibling_hash) in proof.siblings.iter().enumerate() {
            let (left, right) = if is_left_child(current_index) {
                (current_hash, sibling_hash.clone())
            } else {
                (sibling_hash.clone(), current_hash)
            };

            current_hash = hash(&(left + &right));
            current_index = parent_index(current_index);
        }

        current_hash == proof.root
    }
}

// Utility functions to calculate parent, left child, and right child indices
fn parent_index(index: usize) -> usize {
    (index - 1) / 2
}

fn left_child_index(index: usize) -> usize {
    2 * index + 1
}

fn right_child_index(index: usize) -> usize {
    2 * index + 2
}

fn sibling_index(index: usize) -> usize {
    if index % 2 == 0 {
        index - 1
    } else {
        index + 1
    }
}

fn is_left_child(index: usize) -> bool {
    index % 2 != 0
}

// Main function for testing
fn main() {
    let mut tree = MerkleTree::new(4); // Create a Merkle Tree with depth 4
    tree.insert_leaf(0, "data".to_string());

    let proof = tree.get_proof(0).unwrap();
    let mut err_proof = proof.clone();
    let mut err_proof1 = proof.clone();

    dbg!(&proof);
    assert_eq!(tree.prove(proof), true);

    err_proof.value = "data2".to_string();
    dbg!(&err_proof);
    assert_eq!(tree.prove(err_proof), false);

    err_proof1.index = 1;
    dbg!(&err_proof1);
    assert_eq!(tree.prove(err_proof1), false);

    // successf
    dbg!("success");
}
