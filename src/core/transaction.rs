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
use thiserror::Error;
use uuid::Uuid;

/// Derive the canonical address for a hex-encoded ed25519 public key.
///
/// This is the single definition of the address format; [`crate::wallet::Wallet`]
/// delegates to it so an address can never be derived two different ways.
pub fn derive_address(public_key_hex: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(public_key_hex.as_bytes());
    let hash = hex::encode(hasher.finalize());
    format!("0x{}", &hash[..40])
}

/// Errors that can occur while signing a transaction.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum SignError {
    /// The private key was not valid hexadecimal.
    #[error("private key is not valid hex: {0}")]
    InvalidHex(String),

    /// The private key decoded, but was not the 32 bytes ed25519 requires.
    #[error("private key must be 32 bytes, got {0}")]
    InvalidLength(usize),
}

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
    /// Hex-encoded ed25519 public key of the signer.
    ///
    /// Required to verify the signature: `sender` is an address (a hash of this
    /// key), so it cannot be used as a verifying key on its own.
    #[serde(default)]
    pub public_key: Option<String>,
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
            public_key: None,
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
            public_key: None,
            is_coinbase_tx: true,
        }
    }

    /// Create the deterministic coinbase transaction of the genesis block.
    ///
    /// Every node must derive the *same* genesis block, otherwise two honest
    /// nodes are on two different currencies and the genesis check in
    /// [`crate::core::Blockchain::replace_chain`] can never hold. So this one
    /// coinbase has a fixed id and a fixed timestamp instead of a random UUID
    /// and `Utc::now()`.
    pub fn genesis_coinbase(recipient: String, amount: u64) -> Self {
        Self {
            id: "genesis".to_string(),
            sender: "COINBASE".to_string(),
            recipient,
            amount,
            timestamp: DateTime::UNIX_EPOCH,
            signature: Some("COINBASE_SIGNATURE".to_string()),
            public_key: None,
            is_coinbase_tx: true,
        }
    }

    /// Calculate the hash of this transaction
    /// Used for creating Merkle trees and transaction verification
    ///
    /// Every field that affects validation or accounting is in the preimage.
    /// `is_coinbase_tx` and `public_key` in particular: leaving them out let a
    /// user payment be rewritten into a coinbase (which skips signature checks
    /// entirely) without changing the Merkle root or the block hash.
    pub fn hash(&self) -> String {
        let sig = self.signature.as_deref().unwrap_or("");
        let public_key = self.public_key.as_deref().unwrap_or("");
        let tx_data = format!(
            "{}|{}|{}|{}|{}|{}|{}|{}",
            self.id,
            self.sender,
            self.recipient,
            self.amount,
            self.timestamp,
            sig,
            public_key,
            self.is_coinbase_tx
        );
        let mut hasher = Sha256::new();
        hasher.update(tx_data.as_bytes());
        hex::encode(hasher.finalize())
    }

    /// The exact bytes covered by the signature.
    ///
    /// The `id` is inside the payload so it cannot be swapped for a fresh UUID
    /// to sidestep the spent-id index the chain keeps; the fields are separated
    /// so that no two different transactions can share a preimage.
    fn signing_payload(&self) -> String {
        format!(
            "{}|{}|{}|{}|{}",
            self.id, self.sender, self.recipient, self.amount, self.timestamp
        )
    }

    /// Sign the transaction with a hex-encoded 32-byte ed25519 private key.
    ///
    /// Returns [`SignError`] rather than panicking, so a malformed key is a
    /// rejected transaction instead of a downed node.
    pub fn sign(&mut self, private_key: &str) -> Result<(), SignError> {
        use ed25519_dalek::{Signer, SigningKey};

        let key_bytes =
            hex::decode(private_key).map_err(|e| SignError::InvalidHex(e.to_string()))?;
        let key_array: [u8; 32] = key_bytes
            .as_slice()
            .try_into()
            .map_err(|_| SignError::InvalidLength(key_bytes.len()))?;

        let signing_key = SigningKey::from_bytes(&key_array);
        let signature = signing_key.sign(self.signing_payload().as_bytes());
        self.signature = Some(hex::encode(signature.to_bytes()));
        self.public_key = Some(hex::encode(signing_key.verifying_key().to_bytes()));
        Ok(())
    }

    /// Verify the transaction signature using ed25519.
    ///
    /// Three things must hold: the signature is well-formed, the carried public
    /// key actually owns the `sender` address, and the signature is valid over
    /// this transaction's fields. Binding the key to the address is what stops a
    /// valid signature from an unrelated key being accepted as the sender's.
    pub fn verify(&self) -> bool {
        // Coinbase transactions are always valid
        if self.is_coinbase() {
            return true;
        }

        let (Some(signature_hex), Some(public_key_hex)) = (&self.signature, &self.public_key)
        else {
            return false;
        };

        let Ok(sig_bytes) = hex::decode(signature_hex) else {
            return false;
        };
        let Ok(sig_array) = <[u8; 64]>::try_from(sig_bytes.as_slice()) else {
            return false;
        };
        let signature = ed25519_dalek::Signature::from_bytes(&sig_array);

        // The public key must own the sender address. There is exactly one
        // address per key: accepting the raw key as a second identity would give
        // every key two disjoint balances.
        if self.sender != derive_address(public_key_hex) {
            return false;
        }

        let Ok(pub_key_bytes) = hex::decode(public_key_hex) else {
            return false;
        };
        let Ok(pub_key_array) = <[u8; 32]>::try_from(pub_key_bytes.as_slice()) else {
            return false;
        };
        let Ok(verifying_key) = ed25519_dalek::VerifyingKey::from_bytes(&pub_key_array) else {
            return false;
        };

        use ed25519_dalek::Verifier;
        verifying_key
            .verify(self.signing_payload().as_bytes(), &signature)
            .is_ok()
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
        let tx = Transaction::new("alice".to_string(), "bob".to_string(), 100);

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
        let tx = Transaction::new("alice".to_string(), "bob".to_string(), 100);

        let hash = tx.hash();
        assert_eq!(hash.len(), 64); // SHA256 produces 64 hex characters
    }

    #[test]
    fn test_sign_transaction() {
        use ed25519_dalek::SigningKey;
        use rand::rngs::OsRng;

        let signing_key = SigningKey::generate(&mut OsRng);
        let private_key_hex = hex::encode(signing_key.to_bytes());

        let mut tx = Transaction::new("alice".to_string(), "bob".to_string(), 100);

        tx.sign(&private_key_hex)
            .expect("a freshly generated key must sign");
        assert!(tx.signature.is_some());
    }

    /// Build a signed transaction from a fresh key, addressed correctly.
    fn signed_transaction(recipient: &str, amount: u64) -> Transaction {
        use ed25519_dalek::SigningKey;
        use rand::rngs::OsRng;

        let signing_key = SigningKey::generate(&mut OsRng);
        let public_key = hex::encode(signing_key.verifying_key().to_bytes());
        let mut tx = Transaction::new(derive_address(&public_key), recipient.to_string(), amount);
        tx.sign(&hex::encode(signing_key.to_bytes()))
            .expect("a freshly generated key must sign");
        tx
    }

    #[test]
    fn hash_covers_the_coinbase_flag_and_public_key() {
        // Regression: these two fields were outside the hash preimage, so a
        // payment could be rewritten into an (unverified) coinbase without
        // changing the Merkle root or the block hash.
        let tx = signed_transaction("bob", 100);
        let original = tx.hash();

        let mut promoted = tx.clone();
        promoted.is_coinbase_tx = true;
        assert_ne!(
            original,
            promoted.hash(),
            "the coinbase flag must be hashed"
        );

        let mut stripped = tx.clone();
        stripped.public_key = None;
        assert_ne!(original, stripped.hash(), "the public key must be hashed");
    }

    #[test]
    fn signature_covers_the_transaction_id() {
        // The id is inside the signed payload, so an attacker cannot mint a
        // fresh UUID for a captured signature to defeat the spent-id index.
        let tx = signed_transaction("bob", 100);
        assert!(tx.verify());

        let mut relabelled = tx.clone();
        relabelled.id = Uuid::new_v4().to_string();
        assert!(
            !relabelled.verify(),
            "a re-identified transaction must not verify"
        );
    }

    #[test]
    fn raw_public_key_is_not_a_second_identity() {
        use ed25519_dalek::SigningKey;
        use rand::rngs::OsRng;

        // Regression: verify() used to accept `sender == public_key`, giving one
        // keypair two spendable balances.
        let signing_key = SigningKey::generate(&mut OsRng);
        let public_key = hex::encode(signing_key.verifying_key().to_bytes());
        let mut tx = Transaction::new(public_key.clone(), "bob".to_string(), 100);
        tx.sign(&hex::encode(signing_key.to_bytes()))
            .expect("a freshly generated key must sign");

        assert!(
            !tx.verify(),
            "the raw public key is not a valid sender address"
        );
    }

    #[test]
    fn genesis_coinbase_is_deterministic() {
        let a = Transaction::genesis_coinbase("genesis_address".to_string(), 1_000_000);
        let b = Transaction::genesis_coinbase("genesis_address".to_string(), 1_000_000);

        assert_eq!(a.hash(), b.hash());
    }
}
