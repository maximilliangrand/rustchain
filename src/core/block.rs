//! Block module - the fundamental unit of the blockchain
//!
//! A block contains:
//! - Index: Position in the chain
//! - Timestamp: When the block was created
//! - Transactions: List of transactions included in the block
//! - Previous hash: Hash of the previous block (creates the chain)
//! - Merkle root: Root hash of all transactions for efficient verification
//! - Difficulty: The proof-of-work difficulty this block was mined at
//! - Nonce: Proof-of-work solution
//! - Hash: The block's own hash

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::merkle::MerkleTree;
use super::transaction::Transaction;

/// Represents a block in the blockchain
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Block {
    /// Block index/height in the chain
    pub index: u64,
    /// Block creation timestamp
    pub timestamp: DateTime<Utc>,
    /// Transactions included in this block
    pub transactions: Vec<Transaction>,
    /// Hash of the previous block
    pub previous_hash: String,
    /// Merkle root of all transactions
    pub merkle_root: String,
    /// Proof-of-work difficulty this block claims to have been mined at.
    ///
    /// Part of the hash preimage, so it cannot be relabelled after mining, and
    /// checked against the difficulty the chain rules demand at this height,
    /// a block does not get to choose how hard it was.
    ///
    /// Zero on an unmined block, including the genesis block.
    pub difficulty: usize,
    /// Proof-of-work nonce
    pub nonce: u64,
    /// This block's hash
    pub hash: String,
}

impl Block {
    /// Create a new block (not yet mined)
    ///
    /// # Arguments
    /// * `index` - The block's position in the chain
    /// * `transactions` - Transactions to include
    /// * `previous_hash` - Hash of the previous block
    ///
    /// # Example
    /// ```
    /// use rustchain::core::{Block, Transaction};
    ///
    /// let tx = Transaction::new("alice".into(), "bob".into(), 100);
    /// let block = Block::new(1, vec![tx], "previous_hash".to_string());
    /// ```
    pub fn new(index: u64, transactions: Vec<Transaction>, previous_hash: String) -> Self {
        // Calculate Merkle root from transactions
        let tx_hashes: Vec<String> = transactions.iter().map(|tx| tx.hash()).collect();
        let merkle_tree = MerkleTree::new(tx_hashes);

        let mut block = Self {
            index,
            timestamp: Utc::now(),
            transactions,
            previous_hash,
            merkle_root: merkle_tree.root,
            difficulty: 0,
            nonce: 0,
            hash: String::new(),
        };

        block.hash = block.calculate_hash();
        block
    }

    /// Create the genesis block (first block in the chain)
    ///
    /// The genesis block has no previous hash and often contains
    /// a special message or initial distribution of coins
    ///
    /// It is fully deterministic, fixed transaction id and fixed timestamp, so
    /// every node derives the identical genesis hash. Without that, two honest
    /// nodes start from different roots and are, in effect, two currencies.
    pub fn genesis() -> Self {
        let genesis_tx = Transaction::genesis_coinbase(
            "genesis_address".to_string(),
            1_000_000, // Initial coin supply
        );

        let mut block = Self::new(0, vec![genesis_tx], "0".repeat(64));
        block.timestamp = DateTime::UNIX_EPOCH;
        block.hash = block.calculate_hash();
        block
    }

    /// Calculate the hash of this block
    ///
    /// The hash is computed from:
    /// index + timestamp + merkle_root + previous_hash + difficulty + nonce
    pub fn calculate_hash(&self) -> String {
        let block_data = format!(
            "{}{}{}{}{}{}",
            self.index,
            self.timestamp.timestamp_nanos_opt().unwrap_or(0),
            self.merkle_root,
            self.previous_hash,
            self.difficulty,
            self.nonce
        );

        let mut hasher = Sha256::new();
        hasher.update(block_data.as_bytes());
        hex::encode(hasher.finalize())
    }

    /// Mine the block using Proof-of-Work
    ///
    /// Finds a nonce such that the block hash starts with `difficulty` zeros
    ///
    /// The difficulty is recorded on the block before the search starts, so it
    /// is covered by the proof-of-work it describes: a mined block cannot later
    /// be relabelled with a cheaper difficulty without invalidating its hash.
    ///
    /// # Arguments
    /// * `difficulty` - Number of leading zeros required in the hash
    ///
    /// # Returns
    /// The number of iterations (nonces tried)
    ///
    /// # Example
    /// ```
    /// use rustchain::core::{Block, Transaction};
    ///
    /// let tx = Transaction::new("alice".into(), "bob".into(), 100);
    /// let mut block = Block::new(1, vec![tx], "prev_hash".to_string());
    /// let iterations = block.mine(2); // Find hash starting with "00"
    /// assert!(block.hash.starts_with("00"));
    /// ```
    pub fn mine(&mut self, difficulty: usize) -> u64 {
        self.difficulty = difficulty;

        let target = "0".repeat(difficulty);
        let mut iterations = 0u64;

        loop {
            self.hash = self.calculate_hash();
            iterations += 1;

            if self.hash.starts_with(&target) {
                log::info!(
                    "Block {} mined! Nonce: {}, Hash: {}",
                    self.index,
                    self.nonce,
                    self.hash
                );
                return iterations;
            }

            self.nonce += 1;

            // Log progress every million iterations
            if iterations.is_multiple_of(1_000_000) {
                log::debug!("Mining... {} iterations", iterations);
            }
        }
    }

    /// Verify that the block's hash is valid
    ///
    /// Checks that:
    /// 1. The stored hash matches the calculated hash
    /// 2. The hash meets the difficulty requirement (if provided)
    pub fn verify_hash(&self, difficulty: Option<usize>) -> bool {
        let calculated = self.calculate_hash();

        if calculated != self.hash {
            return false;
        }

        if let Some(diff) = difficulty {
            let target = "0".repeat(diff);
            return self.hash.starts_with(&target);
        }

        true
    }

    /// Verify all transactions in the block
    pub fn verify_transactions(&self) -> bool {
        // Check Merkle root
        let tx_hashes: Vec<String> = self.transactions.iter().map(|tx| tx.hash()).collect();
        let merkle_tree = MerkleTree::new(tx_hashes);

        if merkle_tree.root != self.merkle_root {
            log::error!("Merkle root mismatch");
            return false;
        }

        // Verify each transaction
        for tx in &self.transactions {
            if !tx.verify() {
                log::error!("Transaction {} failed verification", tx.id);
                return false;
            }
        }

        true
    }

    /// Get the total value transferred in this block (excluding coinbase)
    ///
    /// A `Block` is deserialized straight off the wire, before any validation
    /// says the amounts are affordable, so the running total is saturated
    /// rather than summed: two transactions of `u64::MAX / 2 + 1` are a report
    /// that reads `u64::MAX`, not a panicking node.
    pub fn total_value(&self) -> u64 {
        self.transactions
            .iter()
            .filter(|tx| !tx.is_coinbase())
            .map(|tx| tx.amount)
            .fold(0u64, u64::saturating_add)
    }

    /// Get the mining reward (coinbase amount) in this block
    pub fn mining_reward(&self) -> u64 {
        self.transactions
            .iter()
            .find(|tx| tx.is_coinbase())
            .map(|tx| tx.amount)
            .unwrap_or(0)
    }

    /// Get transaction count
    pub fn transaction_count(&self) -> usize {
        self.transactions.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_genesis_block() {
        let genesis = Block::genesis();

        assert_eq!(genesis.index, 0);
        assert_eq!(genesis.previous_hash, "0".repeat(64));
        assert_eq!(genesis.transaction_count(), 1);
        assert!(genesis.transactions[0].is_coinbase());
    }

    #[test]
    fn genesis_block_is_deterministic() {
        // Every node must agree on the root of the chain, so the genesis block
        // may not depend on a random UUID or the wall clock.
        assert_eq!(Block::genesis().hash, Block::genesis().hash);
    }

    #[test]
    fn test_create_block() {
        let tx = Transaction::new("alice".into(), "bob".into(), 100);
        let block = Block::new(1, vec![tx], "previous_hash".to_string());

        assert_eq!(block.index, 1);
        assert_eq!(block.previous_hash, "previous_hash");
        assert_eq!(block.transaction_count(), 1);
        assert!(!block.hash.is_empty());
    }

    #[test]
    fn test_calculate_hash() {
        let tx = Transaction::new("alice".into(), "bob".into(), 100);
        let block = Block::new(1, vec![tx], "prev".to_string());

        let hash = block.calculate_hash();
        assert_eq!(hash.len(), 64);
        assert_eq!(hash, block.hash);
    }

    #[test]
    fn test_mine_block() {
        let tx = Transaction::new("alice".into(), "bob".into(), 100);
        let mut block = Block::new(1, vec![tx], "prev".to_string());

        let iterations = block.mine(2); // Low difficulty for fast test

        assert!(block.hash.starts_with("00"));
        assert!(iterations > 0);
    }

    #[test]
    fn mining_records_the_difficulty_it_used() {
        let mut block = Block::new(1, vec![], "prev".to_string());
        assert_eq!(block.difficulty, 0, "an unmined block claims no work");

        block.mine(2);

        assert_eq!(block.difficulty, 2);
    }

    #[test]
    fn the_claimed_difficulty_is_committed_to_the_hash() {
        // The claimed difficulty is only meaningful if it is covered by the
        // proof-of-work: otherwise a block mined at difficulty 1 could be
        // relabelled as difficulty 5 and pass a chain that demands 5.
        let mut block = Block::new(1, vec![], "prev".to_string());
        block.mine(2);
        assert!(block.verify_hash(Some(2)));

        block.difficulty = 5;

        assert!(
            !block.verify_hash(None),
            "relabelling the difficulty must break the block hash"
        );
    }

    #[test]
    fn test_verify_hash() {
        let tx = Transaction::new("alice".into(), "bob".into(), 100);
        let mut block = Block::new(1, vec![tx], "prev".to_string());
        block.mine(2);

        assert!(block.verify_hash(Some(2)));
        assert!(block.verify_hash(None));
    }

    #[test]
    fn test_verify_transactions() {
        use crate::core::transaction::derive_address;
        use ed25519_dalek::SigningKey;
        use rand::rngs::OsRng;

        // The sender must be the address derived from the signing key, otherwise
        // verification correctly refuses the transaction.
        let signing_key = SigningKey::generate(&mut OsRng);
        let public_key = hex::encode(signing_key.verifying_key().to_bytes());
        let mut tx = Transaction::new(derive_address(&public_key), "bob".into(), 100);
        tx.sign(&hex::encode(signing_key.to_bytes()))
            .expect("a freshly generated key must sign");
        let block = Block::new(1, vec![tx], "prev".to_string());

        assert!(block.verify_transactions());
    }

    #[test]
    fn test_total_value() {
        let coinbase = Transaction::coinbase("miner".into(), 50);
        let tx1 = Transaction::new("a".into(), "b".into(), 100);
        let tx2 = Transaction::new("c".into(), "d".into(), 200);

        let block = Block::new(1, vec![coinbase, tx1, tx2], "prev".to_string());

        assert_eq!(block.total_value(), 300);
        assert_eq!(block.mining_reward(), 50);
    }

    #[test]
    fn total_value_saturates_instead_of_overflowing() {
        // Found by `cargo fuzz run block_deserialize`: a block arrives as bytes,
        // and nothing has yet said its amounts are affordable, so summing them
        // used to abort the process on any pair adding past u64::MAX.
        let half = u64::MAX / 2 + 1;
        let block = Block::new(
            1,
            vec![
                Transaction::new("a".into(), "b".into(), half),
                Transaction::new("c".into(), "d".into(), half),
            ],
            "prev".to_string(),
        );

        assert_eq!(block.total_value(), u64::MAX);
    }
}
