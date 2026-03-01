//! Transaction module - represents transfer of value on the blockchain
//!
//! A transaction contains:
//! - Sender address (public key hash)
//! - Recipient address
//! - Amount to transfer
//! - Timestamp
//! - Unique ID
//! - Signature (ed25519 cryptographic signature)

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
    /// Transaction signature (ed25519 signature, hex-encoded)
    pub signature: Option<String>,
    /// Whether this is a coinbase (mining reward) transaction
    #[serde(default)]
    pub is_coinbase_tx: bool,
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
            is_coinbase_tx: false,
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
            is_coinbase_tx: true,
        }
    }

    /// Calculate the hash of this transaction
    /// Used for creating Merkle trees and transaction verification
    pub fn hash(&self) -> String {
        let sig = self.signature.as_deref().unwrap_or("");
        let tx_data = format!(
            "{}{}{}{}{}{}",
            self.id, self.sender, self.recipient, self.amount, self.timestamp, sig
        );
        let mut hasher = Sha256::new();
        hasher.update(tx_data.as_bytes());
        hex::encode(hasher.finalize())
    }

    /// Sign the transaction with an ed25519 private key
    pub fn sign(&mut self, private_key: &str) {
        use ed25519_dalek::{SigningKey, Signer};
        let key_bytes = hex::decode(private_key).expect("Invalid private key hex");
        let signing_key = SigningKey::from_bytes(&key_bytes.try_into().expect("Invalid key length"));
        let message = format!("{}{}{}{}", self.sender, self.recipient, self.amount, self.timestamp);
        let signature = signing_key.sign(message.as_bytes());
        self.signature = Some(hex::encode(signature.to_bytes()));
    }

    /// Verify the transaction signature using ed25519
    /// Returns true if the transaction appears valid
    pub fn verify(&self) -> bool {
        // Coinbase transactions are always valid
        if self.is_coinbase() {
            return true;
        }

        // Check that signature exists
        let signature_hex = match &self.signature {
            Some(s) => s,
            None => return false,
        };

        let sig_bytes = match hex::decode(signature_hex) {
            Ok(b) => b,
            Err(_) => return false,
        };

        let sig_array: [u8; 64] = match sig_bytes.try_into() {
            Ok(a) => a,
            Err(_) => return false,
        };
        let signature = ed25519_dalek::Signature::from_bytes(&sig_array);

        // sender field is the address, we need the public key from the transaction
        // For now, verify the signature is well-formed
        // In production, the public key would be included in the transaction
        let pub_key_bytes = match hex::decode(&self.sender) {
            Ok(b) if b.len() == 32 => b,
            _ => return false,
        };

        let verifying_key = match ed25519_dalek::VerifyingKey::from_bytes(
            &pub_key_bytes.try_into().unwrap_or([0u8; 32]),
        ) {
            Ok(k) => k,
            Err(_) => return false,
        };

        let message = format!("{}{}{}{}", self.sender, self.recipient, self.amount, self.timestamp);
        use ed25519_dalek::Verifier;
        verifying_key.verify(message.as_bytes(), &signature).is_ok()
    }

    /// Check if this is a coinbase transaction
    pub fn is_coinbase(&self) -> bool {
        self.is_coinbase_tx
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
        assert!(!tx.is_coinbase_tx);
    }

    #[test]
    fn test_coinbase_transaction() {
        let tx = Transaction::coinbase("miner".to_string(), 50);

        assert_eq!(tx.sender, "COINBASE");
        assert_eq!(tx.recipient, "miner");
        assert_eq!(tx.amount, 50);
        assert!(tx.is_coinbase());
        assert!(tx.is_coinbase_tx);
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
        use ed25519_dalek::SigningKey;
        use rand::rngs::OsRng;

        let signing_key = SigningKey::generate(&mut OsRng);
        let private_key_hex = hex::encode(signing_key.to_bytes());

        let mut tx = Transaction::new(
            "alice".to_string(),
            "bob".to_string(),
            100,
        );

        tx.sign(&private_key_hex);
        assert!(tx.signature.is_some());
    }
}
