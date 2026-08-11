# RustChain 🦀⛓️

A blockchain implementation from scratch in Rust. Built for educational purposes and as a portfolio project demonstrating deep understanding of blockchain internals.

[![Rust](https://img.shields.io/badge/rust-1.70%2B-orange.svg)](https://www.rust-lang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

## Features

- **Complete Blockchain Implementation**
  - SHA-256 cryptographic hashing
  - Merkle trees for transaction verification, with inclusion proofs
  - Proof-of-Work consensus algorithm
  - UTXO-based balance tracking, derived from the chain rather than stored
  - Chain validation and tamper detection (proof-of-work, signatures, balances, replay)

- **Wallet System**
  - Key pair generation
  - Transaction signing
  - Address derivation

- **P2P Networking**
  - Node discovery and connection, over a length-prefixed message framing
  - Block and transaction propagation
  - Chain synchronization (longest chain rule), persisted to the node's chain file

  Nodes do not mine on their own: blocks are produced with the `mine` command and
  propagate from there.

- **Full CLI Interface**
  - Initialize blockchain
  - Create wallets
  - Send transactions
  - Mine blocks
  - Query balances and history

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        RustChain                             │
├─────────────────────────────────────────────────────────────┤
│  CLI Layer                                                   │
│  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐            │
│  │  init   │ │  mine   │ │  send   │ │  node   │            │
│  └────┬────┘ └────┬────┘ └────┬────┘ └────┬────┘            │
├───────┴───────────┴───────────┴───────────┴─────────────────┤
│  Core Layer                                                  │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐            │
│  │ Blockchain  │ │    Block    │ │ Transaction │            │
│  └─────────────┘ └─────────────┘ └─────────────┘            │
│  ┌─────────────┐ ┌─────────────┐                            │
│  │ Merkle Tree │ │   Wallet    │                            │
│  └─────────────┘ └─────────────┘                            │
├─────────────────────────────────────────────────────────────┤
│  Network Layer                                               │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐            │
│  │    Node     │ │   Message   │ │   Client    │            │
│  └─────────────┘ └─────────────┘ └─────────────┘            │
└─────────────────────────────────────────────────────────────┘
```

## Quick Start

### Prerequisites

- Rust 1.70 or higher
- Cargo package manager

### Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/rustchain.git
cd rustchain

# Build the project
cargo build --release

# Run tests
cargo test
```

### Run the Demo

The easiest way to see RustChain in action:

```bash
cargo run -- demo
```

This will:
1. Create a blockchain with genesis block
2. Create three wallets (Alice, Bob, Miner)
3. Mine blocks and transfer coins
4. Display final balances and validate the chain

### Basic Usage

#### Initialize a Blockchain

```bash
# Create a new blockchain with default difficulty (4)
cargo run -- init

# Create with custom difficulty
cargo run -- init --difficulty 3 --output my_chain.json
```

#### Create a Wallet

```bash
# Create and save a new wallet
cargo run -- wallet create --output alice.json

# View wallet details
cargo run -- wallet show --file alice.json
```

#### Mine Blocks

```bash
# Mine a new block (receive 50 coin reward)
cargo run -- mine --address "your_wallet_address"
```

#### Send Transactions

```bash
# Create a transaction
cargo run -- transaction create \
  --wallet alice.json \
  --to "recipient_address" \
  --amount 100

# View pending transactions
cargo run -- transaction pending
```

#### Query the Blockchain

```bash
# View blockchain info
cargo run -- info
cargo run -- info --verbose

# Check balance
cargo run -- balance "wallet_address"

# View a specific block
cargo run -- block 0  # genesis block
cargo run -- block 1  # first mined block

# Validate the chain
cargo run -- validate
```

#### Run a Node

```bash
# Start a P2P node
cargo run -- node --port 8333

# Connect to peers
cargo run -- node --port 8334 --peers "127.0.0.1:8333"
```

## How It Works

### Block Structure

Each block contains:
- **Index**: Position in the chain
- **Timestamp**: Creation time
- **Transactions**: List of transactions
- **Previous Hash**: Link to previous block
- **Merkle Root**: Root hash of transaction tree
- **Nonce**: Proof-of-Work solution
- **Hash**: Block's own hash

```
Block #1
┌────────────────────────────────────────┐
│ Index: 1                               │
│ Timestamp: 2024-01-15T10:30:00Z        │
│ Previous Hash: 0000abcd...             │
│ Merkle Root: 7f8e2b1a...               │
│ Nonce: 54892                           │
│ Hash: 0000def1...                      │
├────────────────────────────────────────┤
│ Transactions:                          │
│   [COINBASE] 50 -> miner_address       │
│   alice -> bob: 25 coins               │
│   charlie -> david: 10 coins           │
└────────────────────────────────────────┘
```

### Merkle Tree

Transactions are organized in a Merkle tree for efficient verification:

```
                    Root Hash
                   /         \
            Hash(0-1)       Hash(2-3)
            /      \        /      \
        Hash(0)  Hash(1)  Hash(2)  Hash(3)
           |        |        |        |
         Tx 0     Tx 1     Tx 2     Tx 3
```

This allows proving a transaction is included in a block by providing only O(log n) hashes.

### Proof of Work

Mining finds a nonce such that:
```
SHA256(block_data + nonce) < target
```

With difficulty `d`, the hash must start with `d` zeros:
- Difficulty 1: `0xxxxxxx...` (~16 attempts)
- Difficulty 4: `0000xxxx...` (~65,536 attempts)
- Difficulty 8: `00000000...` (~4.3 billion attempts)

### Consensus

Nodes follow the **longest chain rule**:
- The longest *valid* chain wins, and it must share our genesis block
- Every block of an incoming chain is re-validated (proof-of-work, signatures, balances) before it is adopted
- Forks are resolved by chain length; difficulty is fixed, so length is the work
- Transactions not in the winning chain return to the mempool

## Project Structure

```
rustchain/
├── Cargo.toml           # Dependencies and metadata
├── README.md            # This file
├── src/
│   ├── main.rs          # CLI entry point
│   ├── lib.rs           # Library exports
│   ├── core/
│   │   ├── mod.rs       # Core module
│   │   ├── transaction.rs  # Transaction structure
│   │   ├── block.rs     # Block structure
│   │   ├── merkle.rs    # Merkle tree implementation
│   │   └── blockchain.rs   # Blockchain logic
│   ├── wallet/
│   │   └── mod.rs       # Wallet & key management
│   ├── network/
│   │   └── mod.rs       # P2P networking
│   └── cli/
│       └── mod.rs       # Command-line interface
└── tests/               # Integration tests
```

## API Usage (as a Library)

```rust
use rustchain::core::{Blockchain, Transaction};
use rustchain::wallet::Wallet;

fn main() {
    // Create blockchain
    let mut blockchain = Blockchain::with_difficulty(2);

    // Create wallets
    let alice = Wallet::new();
    let bob = Wallet::new();

    // Mine a block (alice gets reward)
    blockchain.mine_pending_transactions(&alice.address).unwrap();

    // Create and add transaction
    let tx = alice.create_transaction(&bob.address, 25).unwrap();
    blockchain.add_transaction(tx).unwrap();

    // Mine block to confirm transaction
    blockchain.mine_pending_transactions(&alice.address).unwrap();

    // Check balances
    println!("Alice: {} coins", blockchain.get_balance(&alice.address));
    println!("Bob: {} coins", blockchain.get_balance(&bob.address));

    // Validate chain
    assert!(blockchain.is_valid().is_ok());
}
```

## Educational Notes

This implementation is designed to demonstrate blockchain concepts clearly. In a production blockchain, you would also need:

- **Real Cryptography**: Use `secp256k1` for ECDSA signatures instead of simplified hashing
- **Persistent Storage**: Use a database (LevelDB, RocksDB) instead of JSON files
- **Full UTXO Model**: Track unspent transaction outputs properly
- **Script System**: Add programmable transaction validation (like Bitcoin Script)
- **Network Security**: Add encryption, authentication, DoS protection
- **Consensus Upgrades**: Consider PoS, PBFT, or other modern consensus mechanisms
- **Light Clients**: SPV verification for mobile/lightweight nodes

## Performance

Benchmarks on Apple M1:

| Operation | Time |
|-----------|------|
| Hash calculation | ~500ns |
| Block mining (difficulty 4) | ~100ms |
| Transaction verification | ~1μs |
| Chain validation (100 blocks) | ~5ms |

## Contributing

Contributions are welcome! Please feel free to submit issues or pull requests.

## License

MIT License - feel free to use this code for learning and building.

## Acknowledgments

- Bitcoin whitepaper by Satoshi Nakamoto
- "Mastering Bitcoin" by Andreas Antonopoulos
- The Rust community for excellent documentation

---

Built with 🦀 by Maxim Gagiev
