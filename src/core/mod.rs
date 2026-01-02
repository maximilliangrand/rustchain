//! Core blockchain components
//!
//! This module contains the fundamental building blocks of the blockchain:
//! - Transactions: Transfer of value between addresses
//! - Blocks: Containers for transactions with proof-of-work
//! - Merkle Trees: Efficient verification of transaction integrity
//! - Blockchain: The chain of blocks with validation logic

pub mod transaction;
pub mod block;
pub mod merkle;
pub mod blockchain;

pub use transaction::Transaction;
pub use block::Block;
pub use merkle::MerkleTree;
pub use blockchain::Blockchain;
