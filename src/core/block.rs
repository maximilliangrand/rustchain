//! Block module - the fundamental unit of the blockchain
//!
//! A block contains:
//! - Index: Position in the chain
//! - Timestamp: When the block was created
//! - Transactions: List of transactions included in the block
//! - Previous hash: Hash of the previous block (creates the chain)
//! - Merkle root: Root hash of all transactions for efficient verification
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
    pub fn genesis() -> Self {
        let genesis_tx = Transaction::coinbase(
            "genesis_address".to_string(),
            1_000_000, // Initial coin supply
        );

        let mut block = Self::new(0, vec![genesis_tx], "0".repeat(64));
        block.hash = block.calculate_hash();
        block
    }

    /// Calculate the hash of this block
    ///
    /// The hash is computed from: index + timestamp + merkle_root + previous_hash + nonce
    pub fn calculate_hash(&self) -> String {
        let block_data = format!(
            "{}{}{}{}{}",
            self.index,
            self.timestamp.timestamp_nanos_opt().unwrap_or(0),
            self.merkle_root,
            self.previous_hash,
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
            if iterations % 1_000_000 == 0 {
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
    pub fn total_value(&self) -> u64 {
        self.transactions
            .iter()
            .filter(|tx| !tx.is_coinbase())
            .map(|tx| tx.amount)
            .sum()
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
    fn test_verify_hash() {
        let tx = Transaction::new("alice".into(), "bob".into(), 100);
        let mut block = Block::new(1, vec![tx], "prev".to_string());
        block.mine(2);

        assert!(block.verify_hash(Some(2)));
        assert!(block.verify_hash(None));
    }

    #[test]
    fn test_verify_transactions() {
        let mut tx = Transaction::new("alice".into(), "bob".into(), 100);
        tx.sign("alice_key");
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
}
