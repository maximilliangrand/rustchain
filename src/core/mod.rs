//! Core blockchain components
//!
//! This module contains the fundamental building blocks of the blockchain:
//! - Transactions: Transfer of value between addresses
//! - Blocks: Containers for transactions with proof-of-work
//! - Merkle Trees: Efficient verification of transaction integrity
//! - Blockchain: The chain of blocks with validation logic
//! - Canonical encoding: The one unambiguous preimage everything above hashes

pub mod block;
pub mod blockchain;
pub(crate) mod hashing;
pub mod merkle;
pub mod transaction;

pub use block::Block;
pub use blockchain::Blockchain;
pub use merkle::MerkleTree;
pub use transaction::Transaction;
