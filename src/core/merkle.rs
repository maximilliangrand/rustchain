//! Merkle Tree implementation for transaction verification
//!
//! A Merkle tree is a binary tree where:
//! - Leaf nodes contain hashes of individual transactions (prefixed with 0x00)
//! - Internal nodes contain hashes of their children concatenated (prefixed with 0x01)
//! - The root hash represents the entire set of transactions
//!
//! Domain separation (leaf vs internal node prefix) prevents second preimage attacks
//! where an attacker could construct a leaf that looks like an internal node.
//!
//! This allows efficient verification that a transaction is included
//! in a block without downloading all transactions (SPV - Simple Payment Verification)

use sha2::{Digest, Sha256};

/// A Merkle Tree for efficient transaction verification
#[derive(Debug, Clone)]
pub struct MerkleTree {
    /// The root hash of the tree
    pub root: String,
    /// All nodes in the tree (stored as a flat array)
    nodes: Vec<String>,
    /// Number of leaf nodes (transactions)
    leaf_count: usize,
}

impl MerkleTree {
    /// Build a Merkle tree from a list of transaction hashes
    ///
    /// # Arguments
    /// * `hashes` - Vector of transaction hashes
    ///
    /// # Returns
    /// A new MerkleTree with computed root hash
    ///
    /// # Example
    /// ```
    /// use rustchain::core::MerkleTree;
    ///
    /// let tx_hashes = vec![
    ///     "hash1".to_string(),
    ///     "hash2".to_string(),
    ///     "hash3".to_string(),
    /// ];
    /// let tree = MerkleTree::new(tx_hashes);
    /// println!("Merkle root: {}", tree.root);
    /// ```
    pub fn new(hashes: Vec<String>) -> Self {
        if hashes.is_empty() {
            return Self {
                root: Self::hash_leaf("empty"),
                nodes: vec![],
                leaf_count: 0,
            };
        }

        let leaf_count = hashes.len();
        // Hash each leaf with domain separation prefix
        let mut nodes: Vec<String> = hashes.iter().map(|h| Self::hash_leaf(h)).collect();

        // If odd number of nodes, duplicate the last one
        if nodes.len() % 2 == 1 {
            nodes.push(nodes.last().unwrap().clone());
        }

        let mut all_nodes = nodes.clone();
        let mut current_level = nodes;

        // Build tree bottom-up
        while current_level.len() > 1 {
            let mut next_level = Vec::new();

            for chunk in current_level.chunks(2) {
                let parent_hash = Self::hash_node(&chunk[0], chunk.get(1).unwrap_or(&chunk[0]));
                next_level.push(parent_hash.clone());
                all_nodes.push(parent_hash);
            }

            // Handle odd number of nodes at this level
            if next_level.len() > 1 && next_level.len() % 2 == 1 {
                next_level.push(next_level.last().unwrap().clone());
            }

            current_level = next_level;
        }

        let root = current_level.first().unwrap_or(&String::new()).clone();

        Self {
            root,
            nodes: all_nodes,
            leaf_count,
        }
    }

    /// Hash a leaf node with domain separation prefix 0x00
    fn hash_leaf(data: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(b"\x00");
        hasher.update(data.as_bytes());
        hex::encode(hasher.finalize())
    }

    /// Hash an internal node with domain separation prefix 0x01
    fn hash_node(left: &str, right: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(b"\x01");
        hasher.update(left.as_bytes());
        hasher.update(right.as_bytes());
        hex::encode(hasher.finalize())
    }

    /// Get the Merkle root hash
    pub fn root_hash(&self) -> &str {
        &self.root
    }

    /// Get the number of transactions (leaves) in the tree
    pub fn transaction_count(&self) -> usize {
        self.leaf_count
    }

    /// Generate a Merkle proof for a transaction at given index
    /// The proof can be used to verify inclusion without the full tree
    ///
    /// # Arguments
    /// * `index` - The index of the transaction to prove
    ///
    /// # Returns
    /// Vector of (hash, is_left) pairs forming the proof path
    pub fn generate_proof(&self, index: usize) -> Option<Vec<(String, bool)>> {
        if index >= self.leaf_count || self.nodes.is_empty() {
            return None;
        }

        let mut proof = Vec::new();
        let mut current_index = index;
        let mut level_size = self.leaf_count;
        let mut level_start = 0;

        // Traverse up the tree
        while level_size > 1 {
            // Account for odd level sizes
            let padded_size = if level_size % 2 == 1 { level_size + 1 } else { level_size };

            // Get sibling
            let sibling_index = if current_index % 2 == 0 {
                current_index + 1
            } else {
                current_index - 1
            };

            let is_left = current_index % 2 == 1;

            if level_start + sibling_index < self.nodes.len() {
                let sibling_global_index = if sibling_index < level_size {
                    level_start + sibling_index
                } else {
                    level_start + level_size - 1 // Duplicate last node for odd sizes
                };

                if sibling_global_index < self.nodes.len() {
                    proof.push((self.nodes[sibling_global_index].clone(), is_left));
                }
            }

            // Move to next level
            level_start += padded_size;
            level_size = (level_size + 1) / 2;
            current_index /= 2;
        }

        Some(proof)
    }

    /// Verify a Merkle proof
    ///
    /// # Arguments
    /// * `tx_hash` - The hash of the transaction to verify
    /// * `proof` - The Merkle proof (from generate_proof)
    /// * `root` - The expected Merkle root
    ///
    /// # Returns
    /// true if the proof is valid
    pub fn verify_proof(tx_hash: &str, proof: &[(String, bool)], root: &str) -> bool {
        let mut current_hash = Self::hash_leaf(tx_hash);

        for (sibling_hash, is_left) in proof {
            if *is_left {
                current_hash = Self::hash_node(sibling_hash, &current_hash);
            } else {
                current_hash = Self::hash_node(&current_hash, sibling_hash);
            }
        }

        current_hash == root
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_tree() {
        let tree = MerkleTree::new(vec![]);
        assert_eq!(tree.transaction_count(), 0);
    }

    #[test]
    fn test_single_transaction() {
        let tree = MerkleTree::new(vec!["tx1_hash".to_string()]);
        assert_eq!(tree.transaction_count(), 1);
        assert!(!tree.root.is_empty());
    }

    #[test]
    fn test_multiple_transactions() {
        let hashes = vec![
            "tx1".to_string(),
            "tx2".to_string(),
            "tx3".to_string(),
            "tx4".to_string(),
        ];
        let tree = MerkleTree::new(hashes);

        assert_eq!(tree.transaction_count(), 4);
        assert!(!tree.root.is_empty());
        assert_eq!(tree.root.len(), 64); // SHA256 hex
    }

    #[test]
    fn test_odd_number_transactions() {
        let hashes = vec![
            "tx1".to_string(),
            "tx2".to_string(),
            "tx3".to_string(),
        ];
        let tree = MerkleTree::new(hashes);

        assert_eq!(tree.transaction_count(), 3);
        assert!(!tree.root.is_empty());
    }

    #[test]
    fn test_same_input_same_root() {
        let hashes1 = vec!["a".to_string(), "b".to_string()];
        let hashes2 = vec!["a".to_string(), "b".to_string()];

        let tree1 = MerkleTree::new(hashes1);
        let tree2 = MerkleTree::new(hashes2);

        assert_eq!(tree1.root, tree2.root);
    }

    #[test]
    fn test_different_input_different_root() {
        let tree1 = MerkleTree::new(vec!["a".to_string(), "b".to_string()]);
        let tree2 = MerkleTree::new(vec!["a".to_string(), "c".to_string()]);

        assert_ne!(tree1.root, tree2.root);
    }

    #[test]
    fn test_domain_separation() {
        // A leaf hash and an internal node hash of the same data should differ
        let leaf = MerkleTree::hash_leaf("test");
        let node = MerkleTree::hash_node("test", "");
        assert_ne!(leaf, node);
    }
}
