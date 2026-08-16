//! Wallet module - key management and transaction signing
//!
//! A wallet contains:
//! - Public/private key pairs (ed25519)
//! - Address generation
//! - Transaction signing

use std::fmt;

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};

use crate::core::transaction::{derive_address, SignError};
use crate::core::Transaction;

/// Represents a wallet with key pairs
///
/// `Debug` is implemented by hand rather than derived so the private key never
/// reaches a log line or a panic message: a derived `Debug` would print it in
/// full. Export stays explicit through `Serialize`/[`Wallet::to_json`], which a
/// caller has to ask for.
#[derive(Clone, Serialize, Deserialize)]
pub struct Wallet {
    /// Wallet address (public key hash)
    pub address: String,
    /// Private key (ed25519 signing key, hex-encoded)
    private_key: String,
    /// Public key (ed25519 verifying key, hex-encoded)
    pub public_key: String,
}

impl fmt::Debug for Wallet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Wallet")
            .field("address", &self.address)
            .field("private_key", &"<redacted>")
            .field("public_key", &self.public_key)
            .finish()
    }
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
    ///
    /// The key comes straight from a CLI argument, so a typo is a rejected
    /// import ([`SignError`]) rather than a panicking process.
    pub fn from_private_key(private_key: &str) -> Result<Self, SignError> {
        let key_bytes =
            hex::decode(private_key).map_err(|e| SignError::InvalidHex(e.to_string()))?;
        let key_array: [u8; 32] = key_bytes
            .as_slice()
            .try_into()
            .map_err(|_| SignError::InvalidLength(key_bytes.len()))?;

        let signing_key = SigningKey::from_bytes(&key_array);
        let verifying_key = signing_key.verifying_key();
        let public_key = hex::encode(verifying_key.to_bytes());
        let address = Self::generate_address(&public_key);

        Ok(Self {
            address,
            private_key: private_key.to_string(),
            public_key,
        })
    }

    /// Generate address from public key.
    ///
    /// Delegates to [`crate::core::transaction::derive_address`] so the wallet and
    /// the verifier can never disagree about what a sender's address is.
    fn generate_address(public_key: &str) -> String {
        derive_address(public_key)
    }

    /// Create and sign a transaction
    pub fn create_transaction(
        &self,
        recipient: &str,
        amount: u64,
    ) -> Result<Transaction, SignError> {
        let mut tx = Transaction::new(self.address.clone(), recipient.to_string(), amount);
        tx.sign(&self.private_key)?;
        Ok(tx)
    }

    /// Sign an existing transaction
    pub fn sign_transaction(&self, transaction: &mut Transaction) -> Result<(), SignError> {
        transaction.sign(&self.private_key)
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
        let wallet2 =
            Wallet::from_private_key(&wallet1.private_key).expect("a wallet's own key must import");

        assert_eq!(wallet1.address, wallet2.address);
        assert_eq!(wallet1.public_key, wallet2.public_key);
    }

    #[test]
    fn importing_a_malformed_key_is_an_error_not_a_panic() {
        // `wallet import` passes this argument straight through, so a typo must
        // not take the process down.
        assert_eq!(
            Wallet::from_private_key("zz").unwrap_err(),
            SignError::InvalidHex("Invalid character 'z' at position 0".to_string())
        );
        assert_eq!(
            Wallet::from_private_key("abc").unwrap_err(),
            SignError::InvalidHex("Odd number of digits".to_string())
        );
        assert_eq!(
            Wallet::from_private_key("abcd").unwrap_err(),
            SignError::InvalidLength(2)
        );
    }

    #[test]
    fn wallet_transaction_actually_verifies() {
        // Regression: the wallet addresses a transaction by address hash, so
        // verification must use the public key carried on the transaction. When
        // it tried to read the address as a key, every real wallet transaction
        // was rejected by the chain.
        let wallet = Wallet::new();
        let tx = wallet
            .create_transaction("recipient_address", 100)
            .expect("a generated wallet key must sign");

        assert!(tx.verify(), "a wallet-signed transaction must verify");
    }

    #[test]
    fn foreign_key_cannot_impersonate_a_sender() {
        // A validly signed transaction is still refused when the signing key does
        // not own the sender address it claims.
        let victim = Wallet::new();
        let attacker = Wallet::new();

        let mut tx = Transaction::new(victim.address.clone(), "bob".to_string(), 100);
        tx.sign(&attacker.private_key)
            .expect("the attacker's key is well-formed");

        assert!(
            !tx.verify(),
            "a signature from a key that does not own the sender address must be refused"
        );
    }

    #[test]
    fn test_create_transaction() {
        let wallet = Wallet::new();
        let tx = wallet
            .create_transaction("recipient_address", 100)
            .expect("a generated wallet key must sign");

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
    fn debug_never_reveals_the_private_key() {
        // A derived Debug would print the signing key straight into any log line
        // or panic message that formatted a wallet.
        let wallet = Wallet::new();
        let rendered = format!("{:?}", wallet);

        assert!(rendered.contains("<redacted>"));
        assert!(
            !rendered.contains(&wallet.private_key),
            "the private key must never appear in Debug output"
        );
    }

    #[test]
    fn test_unique_wallets() {
        let wallet1 = Wallet::new();
        let wallet2 = Wallet::new();

        assert_ne!(wallet1.address, wallet2.address);
    }
}
