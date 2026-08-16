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
//! Odd levels are padded with a constant sentinel (prefix 0x02), never by
//! duplicating the last node. Duplicating is the CVE-2012-2459 bug: `[a, b, c]`
//! and `[a, b, c, c]` would hash to the same root, so two different transaction
//! sets produce the same block hash and a payment can be silently duplicated
//! inside a block. The sentinel lives in its own hash domain, so no leaf and no
//! internal node can ever equal it.
//!
//! This allows efficient verification that a transaction is included
//! in a block without downloading all transactions (SPV - Simple Payment Verification)

use sha2::{Digest, Sha256};

/// A Merkle Tree for efficient transaction verification
#[derive(Debug, Clone)]
pub struct MerkleTree {
    /// The root hash of the tree
    pub root: String,
    /// Every level of the tree, leaves first and root last. Each level below the
    /// root has an even length, so a node's sibling is always present.
    levels: Vec<Vec<String>>,
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
                levels: vec![],
                leaf_count: 0,
            };
        }

        let leaf_count = hashes.len();
        // Hash each leaf with domain separation prefix
        let mut current_level: Vec<String> = hashes.iter().map(|h| Self::hash_leaf(h)).collect();
        let mut levels = Vec::new();

        // Build tree bottom-up
        while current_level.len() > 1 {
            // Pad odd levels with the sentinel, never with a copy of the last
            // node (CVE-2012-2459).
            if !current_level.len().is_multiple_of(2) {
                current_level.push(Self::padding_node());
            }

            let next_level: Vec<String> = current_level
                .chunks(2)
                .map(|chunk| Self::hash_node(&chunk[0], &chunk[1]))
                .collect();

            levels.push(current_level);
            current_level = next_level;
        }

        let root = current_level[0].clone();
        levels.push(current_level);

        Self {
            root,
            levels,
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

    /// The constant used to pad an odd level, in its own domain (prefix 0x02) so
    /// it can never collide with a leaf or an internal node.
    fn padding_node() -> String {
        let mut hasher = Sha256::new();
        hasher.update(b"\x02");
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
        if index >= self.leaf_count || self.levels.is_empty() {
            return None;
        }

        let mut proof = Vec::new();
        let mut current_index = index;

        // Walk every level except the root level; each of those is padded to an
        // even length, so the sibling always exists.
        for level in &self.levels[..self.levels.len() - 1] {
            let sibling_index = if current_index.is_multiple_of(2) {
                current_index + 1
            } else {
                current_index - 1
            };

            let is_left = !current_index.is_multiple_of(2);
            proof.push((level[sibling_index].clone(), is_left));

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
        let hashes = vec!["tx1".to_string(), "tx2".to_string(), "tx3".to_string()];
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
    fn duplicated_last_leaf_changes_the_root() {
        // Regression (CVE-2012-2459): padding an odd level by duplicating the
        // last node made [a, b, c] and [a, b, c, c] share a root, which let an
        // attacker repeat the last payment of a block without changing the
        // block hash.
        let three = MerkleTree::new(vec!["a".to_string(), "b".to_string(), "c".to_string()]);
        let three_plus_duplicate = MerkleTree::new(vec![
            "a".to_string(),
            "b".to_string(),
            "c".to_string(),
            "c".to_string(),
        ]);

        assert_ne!(three.root, three_plus_duplicate.root);
    }

    #[test]
    fn proofs_verify_against_the_root_for_every_size() {
        // Regression: proofs used to fail their own tree for 1, 5, 6 and 9
        // leaves because the level offsets drifted on odd levels.
        for leaf_count in 1..=9 {
            let hashes: Vec<String> = (0..leaf_count).map(|i| format!("tx{}", i)).collect();
            let tree = MerkleTree::new(hashes.clone());

            for (index, hash) in hashes.iter().enumerate() {
                let proof = tree
                    .generate_proof(index)
                    .unwrap_or_else(|| panic!("no proof for leaf {} of {}", index, leaf_count));

                assert!(
                    MerkleTree::verify_proof(hash, &proof, &tree.root),
                    "proof for leaf {} of {} did not verify",
                    index,
                    leaf_count
                );
            }
        }
    }

    #[test]
    fn proof_of_a_foreign_transaction_is_refused() {
        let tree = MerkleTree::new(vec!["a".to_string(), "b".to_string(), "c".to_string()]);
        let proof = tree.generate_proof(0).expect("leaf 0 exists");

        assert!(!MerkleTree::verify_proof(
            "not_in_the_tree",
            &proof,
            &tree.root
        ));
    }

    #[test]
    fn proof_out_of_range_is_none() {
        let tree = MerkleTree::new(vec!["a".to_string(), "b".to_string()]);

        assert!(tree.generate_proof(2).is_none());
        assert!(MerkleTree::new(vec![]).generate_proof(0).is_none());
    }

    #[test]
    fn test_domain_separation() {
        // A leaf hash and an internal node hash of the same data should differ
        let leaf = MerkleTree::hash_leaf("test");
        let node = MerkleTree::hash_node("test", "");
        assert_ne!(leaf, node);
    }
}
