//! # RustChain
//!
//! A blockchain implementation from scratch in Rust.
//!
//! This is an educational project demonstrating core blockchain concepts:
//! - Cryptographic hashing (SHA-256)
//! - Merkle trees for transaction verification
//! - Proof-of-Work consensus
//! - P2P networking
//! - Wallet and transaction signing
//!
//! ## Quick Start
//!
//! ```rust
//! use rustchain::core::{Blockchain, Transaction};
//! use rustchain::wallet::Wallet;
//!
//! // Create a new blockchain
//! let mut blockchain = Blockchain::with_difficulty(2);
//!
//! // Create wallets
//! let alice = Wallet::new();
//! let bob = Wallet::new();
//!
//! // The genesis block gives coins to genesis_address
//! // In a real scenario, Alice would need to receive coins first
//!
//! // Mine some blocks
//! blockchain.mine_pending_transactions(&alice.address).expect("a fresh block is valid");
//!
//! // Check balance
//! println!("Alice's balance: {}", blockchain.get_balance(&alice.address));
//! ```
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                        RustChain                             │
//! ├─────────────────────────────────────────────────────────────┤
//! │  CLI Layer                                                   │
//! │  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐            │
//! │  │  init   │ │  mine   │ │  send   │ │  node   │            │
//! │  └────┬────┘ └────┬────┘ └────┬────┘ └────┬────┘            │
//! ├───────┴───────────┴───────────┴───────────┴─────────────────┤
//! │  Core Layer                                                  │
//! │  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐            │
//! │  │ Blockchain  │ │   Block     │ │ Transaction │            │
//! │  └─────────────┘ └─────────────┘ └─────────────┘            │
//! │  ┌─────────────┐ ┌─────────────┐                            │
//! │  │ Merkle Tree │ │   Wallet    │                            │
//! │  └─────────────┘ └─────────────┘                            │
//! ├─────────────────────────────────────────────────────────────┤
//! │  Network Layer                                               │
//! │  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐            │
//! │  │    Node     │ │   Message   │ │   Client    │            │
//! │  └─────────────┘ └─────────────┘ └─────────────┘            │
//! └─────────────────────────────────────────────────────────────┘
//! ```

#![warn(missing_docs)]
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_in_result
)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

pub mod cli;
pub mod core;
pub mod network;
pub mod wallet;

pub use core::{Block, Blockchain, MerkleTree, Transaction};
pub use wallet::Wallet;
