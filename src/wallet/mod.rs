//! Wallet module - key management and transaction signing
//!
//! A wallet contains:
//! - Public/private key pairs (ed25519)
//! - Address generation
//! - Transaction signing

use sha2::{Digest, Sha256};
use serde::{Deserialize, Serialize};
use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::rngs::OsRng;

use crate::core::Transaction;

/// Represents a wallet with key pairs
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Wallet {
    /// Wallet address (public key hash)
    pub address: String,
    /// Private key (ed25519 signing key, hex-encoded)
    private_key: String,
    /// Public key (ed25519 verifying key, hex-encoded)
    pub public_key: String,
}

impl Wallet {
    /// Create a new wallet with generated keys
    ///
    /// # Example
    /// ```
    /// use rustchain::wallet::Wallet;
    ///
    /// let wallet = Wallet::new();
    /// println!("Address: {}", wallet.address);
    /// ```
    pub fn new() -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        let private_key = hex::encode(signing_key.to_bytes());
        let public_key = hex::encode(verifying_key.to_bytes());
        let address = Self::generate_address(&public_key);

        Wallet {
            private_key,
            public_key,
            address,
        }
    }

    /// Create a wallet from an existing private key
    pub fn from_private_key(private_key: &str) -> Self {
        let key_bytes = hex::decode(private_key).expect("Invalid private key hex");
        let signing_key = SigningKey::from_bytes(
            &key_bytes.try_into().expect("Invalid key length: expected 32 bytes"),
        );
        let verifying_key = signing_key.verifying_key();
        let public_key = hex::encode(verifying_key.to_bytes());
        let address = Self::generate_address(&public_key);

        Self {
            address,
            private_key: private_key.to_string(),
            public_key,
        }
    }

    /// Generate address from public key
    fn generate_address(public_key: &str) -> String {
        // Simplified: in production use RIPEMD-160(SHA-256(public_key))
        let mut hasher = Sha256::new();
        hasher.update(public_key.as_bytes());
        let hash = hex::encode(hasher.finalize());
        // Take first 40 characters as address
        format!("0x{}", &hash[..40])
    }

    /// Create and sign a transaction
    pub fn create_transaction(&self, recipient: &str, amount: u64) -> Transaction {
        let mut tx = Transaction::new(
            self.address.clone(),
            recipient.to_string(),
            amount,
        );
        tx.sign(&self.private_key);
        tx
    }

    /// Sign an existing transaction
    pub fn sign_transaction(&self, transaction: &mut Transaction) {
        transaction.sign(&self.private_key);
    }

    /// Get the wallet address
    pub fn get_address(&self) -> &str {
        &self.address
    }

    /// Export wallet to JSON (careful with private key!)
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// Import wallet from JSON
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }
}

impl Default for Wallet {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_wallet() {
        let wallet = Wallet::new();

        assert!(wallet.address.starts_with("0x"));
        assert_eq!(wallet.address.len(), 42); // 0x + 40 hex chars
        assert_eq!(wallet.public_key.len(), 64);
    }

    #[test]
    fn test_from_private_key() {
        let wallet1 = Wallet::new();
        let wallet2 = Wallet::from_private_key(&wallet1.private_key);

        assert_eq!(wallet1.address, wallet2.address);
        assert_eq!(wallet1.public_key, wallet2.public_key);
    }

    #[test]
    fn test_create_transaction() {
        let wallet = Wallet::new();
        let tx = wallet.create_transaction("recipient_address", 100);

        assert_eq!(tx.sender, wallet.address);
        assert_eq!(tx.recipient, "recipient_address");
        assert_eq!(tx.amount, 100);
        assert!(tx.signature.is_some());
    }

    #[test]
    fn test_wallet_serialization() {
        let wallet = Wallet::new();
        let json = wallet.to_json().unwrap();
        let restored = Wallet::from_json(&json).unwrap();

        assert_eq!(wallet.address, restored.address);
    }

    #[test]
    fn test_unique_wallets() {
        let wallet1 = Wallet::new();
        let wallet2 = Wallet::new();

        assert_ne!(wallet1.address, wallet2.address);
    }
}
