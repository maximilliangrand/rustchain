//! Transaction module - represents transfer of value on the blockchain
//!
//! A transaction contains:
//! - Sender address (public key hash)
//! - Recipient address
//! - Amount to transfer
//! - Timestamp
//! - Unique ID
//! - Signature (simplified for educational purposes)

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

/// Represents a transaction on the blockchain
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Transaction {
    /// Unique identifier for this transaction
    pub id: String,
    /// Sender's address (public key hash)
    pub sender: String,
    /// Recipient's address
    pub recipient: String,
    /// Amount to transfer
    pub amount: u64,
    /// Transaction timestamp
    pub timestamp: DateTime<Utc>,
    /// Transaction signature (simplified - in production would be cryptographic signature)
    pub signature: Option<String>,
}

impl Transaction {
    /// Create a new transaction
    ///
    /// # Arguments
    /// * `sender` - The sender's address
    /// * `recipient` - The recipient's address
    /// * `amount` - The amount to transfer
    ///
    /// # Example
    /// ```
    /// use rustchain::core::Transaction;
    ///
    /// let tx = Transaction::new(
    ///     "alice_address".to_string(),
    ///     "bob_address".to_string(),
    ///     100,
    /// );
    /// ```
    pub fn new(sender: String, recipient: String, amount: u64) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            sender,
            recipient,
            amount,
            timestamp: Utc::now(),
            signature: None,
        }
    }

    /// Create a coinbase transaction (mining reward)
    /// Coinbase transactions have no sender and create new coins
    ///
    /// # Arguments
    /// * `recipient` - The miner's address who receives the reward
    /// * `amount` - The mining reward amount
    pub fn coinbase(recipient: String, amount: u64) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            sender: "COINBASE".to_string(),
            recipient,
            amount,
            timestamp: Utc::now(),
            signature: Some("COINBASE_SIGNATURE".to_string()),
        }
    }

    /// Calculate the hash of this transaction
    /// Used for creating Merkle trees and transaction verification
    pub fn hash(&self) -> String {
        let tx_data = format!(
            "{}{}{}{}{}",
            self.id, self.sender, self.recipient, self.amount, self.timestamp
        );
        let mut hasher = Sha256::new();
        hasher.update(tx_data.as_bytes());
        hex::encode(hasher.finalize())
    }

    /// Sign the transaction (simplified implementation)
    /// In a real blockchain, this would use asymmetric cryptography
    pub fn sign(&mut self, private_key: &str) {
        let data_to_sign = format!("{}{}{}{}", self.sender, self.recipient, self.amount, private_key);
        let mut hasher = Sha256::new();
        hasher.update(data_to_sign.as_bytes());
        self.signature = Some(hex::encode(hasher.finalize()));
    }

    /// Verify the transaction signature (simplified)
    /// Returns true if the transaction appears valid
    pub fn verify(&self) -> bool {
        // Coinbase transactions are always valid
        if self.sender == "COINBASE" {
            return true;
        }

        // Check that signature exists
        if self.signature.is_none() {
            return false;
        }

        // In a real implementation, we would verify the cryptographic signature
        // using the sender's public key
        true
    }

    /// Check if this is a coinbase transaction
    pub fn is_coinbase(&self) -> bool {
        self.sender == "COINBASE"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_transaction() {
        let tx = Transaction::new(
            "alice".to_string(),
            "bob".to_string(),
            100,
        );

        assert_eq!(tx.sender, "alice");
        assert_eq!(tx.recipient, "bob");
        assert_eq!(tx.amount, 100);
        assert!(tx.signature.is_none());
    }

    #[test]
    fn test_coinbase_transaction() {
        let tx = Transaction::coinbase("miner".to_string(), 50);

        assert_eq!(tx.sender, "COINBASE");
        assert_eq!(tx.recipient, "miner");
        assert_eq!(tx.amount, 50);
        assert!(tx.is_coinbase());
        assert!(tx.verify());
    }

    #[test]
    fn test_transaction_hash() {
        let tx = Transaction::new(
            "alice".to_string(),
            "bob".to_string(),
            100,
        );

        let hash = tx.hash();
        assert_eq!(hash.len(), 64); // SHA256 produces 64 hex characters
    }

    #[test]
    fn test_sign_transaction() {
        let mut tx = Transaction::new(
            "alice".to_string(),
            "bob".to_string(),
            100,
        );

        tx.sign("alice_private_key");
        assert!(tx.signature.is_some());
        assert!(tx.verify());
    }
}
