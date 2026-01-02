//! Blockchain module - the chain of blocks with validation logic
//!
//! The blockchain maintains:
//! - The chain of blocks from genesis to tip
//! - Validation rules for new blocks
//! - UTXO set (balances) tracking
//! - Mempool for pending transactions

use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::block::Block;
use super::transaction::Transaction;

/// Mining difficulty (number of leading zeros required)
pub const DEFAULT_DIFFICULTY: usize = 4;

/// Mining reward
pub const MINING_REWARD: u64 = 50;

/// Blockchain errors
#[derive(Error, Debug)]
pub enum BlockchainError {
    #[error("Invalid block: {0}")]
    InvalidBlock(String),

    #[error("Invalid transaction: {0}")]
    InvalidTransaction(String),

    #[error("Insufficient balance: has {has}, needs {needs}")]
    InsufficientBalance { has: u64, needs: u64 },

    #[error("Invalid chain: {0}")]
    InvalidChain(String),

    #[error("Block not found: {0}")]
    BlockNotFound(String),
}

/// The main blockchain structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Blockchain {
    /// The chain of blocks
    pub chain: Vec<Block>,
    /// Current mining difficulty
    pub difficulty: usize,
    /// Pending transactions (mempool)
    #[serde(skip)]
    pub pending_transactions: Vec<Transaction>,
    /// Mining reward
    pub mining_reward: u64,
    /// Address balances (UTXO simplified)
    balances: HashMap<String, u64>,
}

impl Blockchain {
    /// Create a new blockchain with genesis block
    ///
    /// # Example
    /// ```
    /// use rustchain::core::Blockchain;
    ///
    /// let blockchain = Blockchain::new();
    /// assert_eq!(blockchain.len(), 1); // Genesis block
    /// ```
    pub fn new() -> Self {
        let genesis = Block::genesis();
        let mut balances = HashMap::new();

        // Initialize genesis balances
        for tx in &genesis.transactions {
            *balances.entry(tx.recipient.clone()).or_insert(0) += tx.amount;
        }

        Self {
            chain: vec![genesis],
            difficulty: DEFAULT_DIFFICULTY,
            pending_transactions: Vec::new(),
            mining_reward: MINING_REWARD,
            balances,
        }
    }

    /// Create a blockchain with custom difficulty
    pub fn with_difficulty(difficulty: usize) -> Self {
        let mut blockchain = Self::new();
        blockchain.difficulty = difficulty;
        blockchain
    }

    /// Get the latest block in the chain
    pub fn latest_block(&self) -> &Block {
        self.chain.last().expect("Chain should never be empty")
    }

    /// Get the chain length
    pub fn len(&self) -> usize {
        self.chain.len()
    }

    /// Check if chain is empty (should never be true after initialization)
    pub fn is_empty(&self) -> bool {
        self.chain.is_empty()
    }

    /// Get balance of an address
    pub fn get_balance(&self, address: &str) -> u64 {
        *self.balances.get(address).unwrap_or(&0)
    }

    /// Add a transaction to the mempool
    ///
    /// # Arguments
    /// * `transaction` - The transaction to add
    ///
    /// # Returns
    /// Ok(()) if valid, Err if invalid
    pub fn add_transaction(&mut self, transaction: Transaction) -> Result<(), BlockchainError> {
        // Validate transaction
        if !transaction.verify() {
            return Err(BlockchainError::InvalidTransaction(
                "Signature verification failed".to_string(),
            ));
        }

        // Check sender balance (skip for coinbase)
        if !transaction.is_coinbase() {
            let sender_balance = self.get_balance(&transaction.sender);
            if sender_balance < transaction.amount {
                return Err(BlockchainError::InsufficientBalance {
                    has: sender_balance,
                    needs: transaction.amount,
                });
            }
        }

        // Check for double-spend in mempool
        let pending_spent: u64 = self
            .pending_transactions
            .iter()
            .filter(|tx| tx.sender == transaction.sender)
            .map(|tx| tx.amount)
            .sum();

        let available = self.get_balance(&transaction.sender).saturating_sub(pending_spent);
        if !transaction.is_coinbase() && available < transaction.amount {
            return Err(BlockchainError::InsufficientBalance {
                has: available,
                needs: transaction.amount,
            });
        }

        self.pending_transactions.push(transaction);
        Ok(())
    }

    /// Mine pending transactions into a new block
    ///
    /// # Arguments
    /// * `miner_address` - Address to receive mining reward
    ///
    /// # Returns
    /// The newly mined block
    pub fn mine_pending_transactions(&mut self, miner_address: &str) -> Block {
        // Create coinbase transaction (mining reward)
        let coinbase = Transaction::coinbase(miner_address.to_string(), self.mining_reward);

        // Gather transactions for new block
        let mut transactions = vec![coinbase];
        transactions.append(&mut self.pending_transactions);

        // Create and mine the block
        let previous_hash = self.latest_block().hash.clone();
        let mut block = Block::new(self.chain.len() as u64, transactions, previous_hash);

        log::info!(
            "Mining block {} with {} transactions (difficulty: {})...",
            block.index,
            block.transaction_count(),
            self.difficulty
        );

        let iterations = block.mine(self.difficulty);
        log::info!("Block mined in {} iterations", iterations);

        // Add block to chain
        self.add_block(block.clone()).expect("Freshly mined block should be valid");

        block
    }

    /// Add a block to the chain (after validation)
    ///
    /// # Arguments
    /// * `block` - The block to add
    ///
    /// # Returns
    /// Ok(()) if valid and added, Err otherwise
    pub fn add_block(&mut self, block: Block) -> Result<(), BlockchainError> {
        // Validate the block
        self.validate_block(&block)?;

        // Update balances
        for tx in &block.transactions {
            if !tx.is_coinbase() {
                let sender_balance = self.balances.entry(tx.sender.clone()).or_insert(0);
                *sender_balance = sender_balance.saturating_sub(tx.amount);
            }
            *self.balances.entry(tx.recipient.clone()).or_insert(0) += tx.amount;
        }

        self.chain.push(block);
        Ok(())
    }

    /// Validate a block before adding to chain
    fn validate_block(&self, block: &Block) -> Result<(), BlockchainError> {
        let latest = self.latest_block();

        // Check index
        if block.index != latest.index + 1 {
            return Err(BlockchainError::InvalidBlock(format!(
                "Invalid index: expected {}, got {}",
                latest.index + 1,
                block.index
            )));
        }

        // Check previous hash
        if block.previous_hash != latest.hash {
            return Err(BlockchainError::InvalidBlock(
                "Previous hash mismatch".to_string(),
            ));
        }

        // Verify block hash meets difficulty
        if !block.verify_hash(Some(self.difficulty)) {
            return Err(BlockchainError::InvalidBlock(
                "Block hash doesn't meet difficulty requirement".to_string(),
            ));
        }

        // Verify transactions
        if !block.verify_transactions() {
            return Err(BlockchainError::InvalidBlock(
                "Transaction verification failed".to_string(),
            ));
        }

        // Verify coinbase
        let coinbase_count = block.transactions.iter().filter(|tx| tx.is_coinbase()).count();
        if coinbase_count != 1 {
            return Err(BlockchainError::InvalidBlock(format!(
                "Block must have exactly 1 coinbase transaction, has {}",
                coinbase_count
            )));
        }

        Ok(())
    }

    /// Validate the entire blockchain
    ///
    /// Checks that:
    /// 1. Genesis block is valid
    /// 2. Each block correctly references the previous
    /// 3. All hashes are valid
    /// 4. All transactions are valid
    pub fn is_valid(&self) -> Result<(), BlockchainError> {
        if self.chain.is_empty() {
            return Err(BlockchainError::InvalidChain("Chain is empty".to_string()));
        }

        // Validate genesis block
        let genesis = &self.chain[0];
        if genesis.index != 0 || genesis.previous_hash != "0".repeat(64) {
            return Err(BlockchainError::InvalidChain(
                "Invalid genesis block".to_string(),
            ));
        }

        // Validate rest of chain
        for i in 1..self.chain.len() {
            let current = &self.chain[i];
            let previous = &self.chain[i - 1];

            // Check index
            if current.index != previous.index + 1 {
                return Err(BlockchainError::InvalidChain(format!(
                    "Invalid index at block {}",
                    i
                )));
            }

            // Check hash link
            if current.previous_hash != previous.hash {
                return Err(BlockchainError::InvalidChain(format!(
                    "Hash mismatch at block {}",
                    i
                )));
            }

            // Verify block hash
            if current.calculate_hash() != current.hash {
                return Err(BlockchainError::InvalidChain(format!(
                    "Invalid hash at block {}",
                    i
                )));
            }

            // Verify transactions
            if !current.verify_transactions() {
                return Err(BlockchainError::InvalidChain(format!(
                    "Invalid transactions at block {}",
                    i
                )));
            }
        }

        Ok(())
    }

    /// Get block by index
    pub fn get_block(&self, index: u64) -> Option<&Block> {
        self.chain.get(index as usize)
    }

    /// Get block by hash
    pub fn get_block_by_hash(&self, hash: &str) -> Option<&Block> {
        self.chain.iter().find(|b| b.hash == hash)
    }

    /// Get all transactions for an address
    pub fn get_transactions_for_address(&self, address: &str) -> Vec<&Transaction> {
        self.chain
            .iter()
            .flat_map(|block| &block.transactions)
            .filter(|tx| tx.sender == address || tx.recipient == address)
            .collect()
    }

    /// Get total coins in circulation
    pub fn total_supply(&self) -> u64 {
        self.balances.values().sum()
    }

    /// Get the total number of transactions in the chain
    pub fn total_transactions(&self) -> usize {
        self.chain.iter().map(|b| b.transaction_count()).sum()
    }

    /// Export chain to JSON
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// Import chain from JSON
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }

    /// Replace chain with a longer valid chain (for consensus)
    pub fn replace_chain(&mut self, new_chain: Vec<Block>) -> Result<(), BlockchainError> {
        // New chain must be longer
        if new_chain.len() <= self.chain.len() {
            return Err(BlockchainError::InvalidChain(
                "New chain is not longer than current chain".to_string(),
            ));
        }

        // Create temporary blockchain to validate
        let mut temp = Self::new();
        temp.chain = vec![new_chain[0].clone()];
        temp.difficulty = self.difficulty;

        for block in new_chain.iter().skip(1) {
            temp.add_block(block.clone())?;
        }

        // Replace our chain
        self.chain = new_chain;
        self.balances = temp.balances;

        Ok(())
    }
}

impl Default for Blockchain {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_blockchain() -> Blockchain {
        Blockchain::with_difficulty(2) // Low difficulty for fast tests
    }

    #[test]
    fn test_new_blockchain() {
        let bc = create_test_blockchain();

        assert_eq!(bc.len(), 1);
        assert!(bc.is_valid().is_ok());
    }

    #[test]
    fn test_genesis_balance() {
        let bc = create_test_blockchain();

        assert_eq!(bc.get_balance("genesis_address"), 1_000_000);
    }

    #[test]
    fn test_add_transaction() {
        let mut bc = create_test_blockchain();

        let mut tx = Transaction::new(
            "genesis_address".to_string(),
            "bob".to_string(),
            100,
        );
        tx.sign("genesis_private_key"); // Sign the transaction

        assert!(bc.add_transaction(tx).is_ok());
        assert_eq!(bc.pending_transactions.len(), 1);
    }

    #[test]
    fn test_insufficient_balance() {
        let mut bc = create_test_blockchain();

        let mut tx = Transaction::new(
            "empty_address".to_string(),
            "bob".to_string(),
            100,
        );
        tx.sign("empty_private_key"); // Sign the transaction

        let result = bc.add_transaction(tx);
        assert!(matches!(result, Err(BlockchainError::InsufficientBalance { .. })));
    }

    #[test]
    fn test_mine_block() {
        let mut bc = create_test_blockchain();

        let mut tx = Transaction::new(
            "genesis_address".to_string(),
            "bob".to_string(),
            100,
        );
        tx.sign("genesis_private_key"); // Sign the transaction
        bc.add_transaction(tx).unwrap();

        let block = bc.mine_pending_transactions("miner");

        assert_eq!(bc.len(), 2);
        assert!(block.hash.starts_with("00"));
        assert!(bc.is_valid().is_ok());
    }

    #[test]
    fn test_balance_after_mining() {
        let mut bc = create_test_blockchain();

        let mut tx = Transaction::new(
            "genesis_address".to_string(),
            "bob".to_string(),
            100,
        );
        tx.sign("genesis_private_key"); // Sign the transaction
        bc.add_transaction(tx).unwrap();
        bc.mine_pending_transactions("miner");

        assert_eq!(bc.get_balance("bob"), 100);
        assert_eq!(bc.get_balance("genesis_address"), 1_000_000 - 100);
        assert_eq!(bc.get_balance("miner"), MINING_REWARD);
    }

    #[test]
    fn test_chain_validation() {
        let mut bc = create_test_blockchain();

        bc.mine_pending_transactions("miner");
        bc.mine_pending_transactions("miner");

        assert!(bc.is_valid().is_ok());
    }

    #[test]
    fn test_tamper_detection() {
        let mut bc = create_test_blockchain();
        bc.mine_pending_transactions("miner");

        // Tamper with a block
        bc.chain[1].transactions[0].amount = 999999;

        assert!(bc.is_valid().is_err());
    }

    #[test]
    fn test_json_serialization() {
        let bc = create_test_blockchain();

        let json = bc.to_json().unwrap();
        let restored = Blockchain::from_json(&json).unwrap();

        assert_eq!(bc.len(), restored.len());
        assert_eq!(bc.latest_block().hash, restored.latest_block().hash);
    }
}
