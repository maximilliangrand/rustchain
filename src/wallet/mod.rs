//! Wallet module - key management and transaction signing
//!
//! A wallet contains:
//! - Public/private key pairs (simplified)
//! - Address generation
//! - Transaction signing

use sha2::{Digest, Sha256};
use serde::{Deserialize, Serialize};

use crate::core::Transaction;

/// Represents a wallet with key pairs
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Wallet {
    /// Wallet address (public key hash)
    pub address: String,
    /// Private key (simplified - in production use proper crypto)
    private_key: String,
    /// Public key
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
        // Generate a random private key (simplified)
        let private_key = Self::generate_private_key();
        let public_key = Self::derive_public_key(&private_key);
        let address = Self::derive_address(&public_key);

        Self {
            address,
            private_key,
            public_key,
        }
    }

    /// Create a wallet from an existing private key
    pub fn from_private_key(private_key: &str) -> Self {
        let public_key = Self::derive_public_key(private_key);
        let address = Self::derive_address(&public_key);

        Self {
            address,
            private_key: private_key.to_string(),
            public_key,
        }
    }

    /// Generate a random private key
    fn generate_private_key() -> String {
        // In production, use proper cryptographic random number generation
        let random_bytes: Vec<u8> = (0..32)
            .map(|_| rand_simple())
            .collect();
        hex::encode(random_bytes)
    }

    /// Derive public key from private key
    fn derive_public_key(private_key: &str) -> String {
        // Simplified: in production use elliptic curve cryptography
        let mut hasher = Sha256::new();
        hasher.update(format!("public:{}", private_key).as_bytes());
        hex::encode(hasher.finalize())
    }

    /// Derive address from public key
    fn derive_address(public_key: &str) -> String {
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

/// Simple pseudo-random number generator (not cryptographically secure!)
/// In production, use `rand` crate or OS random
fn rand_simple() -> u8 {
    use std::time::{SystemTime, UNIX_EPOCH};
    static mut SEED: u64 = 0;
    unsafe {
        if SEED == 0 {
            SEED = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos() as u64;
        }
        SEED = SEED.wrapping_mul(1103515245).wrapping_add(12345);
        (SEED >> 16) as u8
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
        let private_key = "my_secret_key";
        let wallet1 = Wallet::from_private_key(private_key);
        let wallet2 = Wallet::from_private_key(private_key);

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
        assert!(tx.verify());
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
        std::thread::sleep(std::time::Duration::from_millis(1));
        let wallet2 = Wallet::new();

        assert_ne!(wallet1.address, wallet2.address);
    }
}
