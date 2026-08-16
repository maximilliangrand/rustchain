# RustChain 🦀⛓️

A blockchain implementation from scratch in Rust. Built for educational purposes and as a portfolio project demonstrating deep understanding of blockchain internals.

[![CI](https://github.com/maximilliangrand/rustchain/actions/workflows/ci.yml/badge.svg)](https://github.com/maximilliangrand/rustchain/actions/workflows/ci.yml)
[![Rust](https://img.shields.io/badge/rust-1.90%2B-orange.svg)](https://www.rust-lang.org/)
[![Edition](https://img.shields.io/badge/edition-2021-orange.svg)](https://doc.rust-lang.org/edition-guide/rust-2021/index.html)
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

- Rust 1.90 or higher
- Cargo package manager

### Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/rustchain.git
cd rustchain

# Build the project
cargo build --release

# Run tests (unit, property-based, and doc tests)
cargo test
```

### Property Tests and Fuzzing

`tests/properties.rs` checks the consensus invariants against randomized inputs
rather than hand-picked ones: a mined chain stays valid and conserves coins,
`replace_chain` adopts a candidate exactly when it is longer *and* valid, a
sender can never commit more than it holds, every Merkle proof verifies against
its own root, and a signature verifies only while its payload is untouched.
These run as part of `cargo test`.

The `fuzz/` crate covers the other half, the bytes a node takes from a peer or
from disk, with [`cargo-fuzz`](https://github.com/rust-fuzz/cargo-fuzz) targets
for transaction, block, message and chain decoding:

```bash
cargo install cargo-fuzz
cargo +nightly fuzz build
cargo +nightly fuzz run block_deserialize \
    fuzz/corpus/block_deserialize fuzz/seeds/block_deserialize -- -max_total_time=60
```

See [`fuzz/README.md`](fuzz/README.md) for the full target list.

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
# Create a new blockchain with the default starting difficulty (4)
cargo run -- init

# Create with a custom starting difficulty
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

### Difficulty Retargeting

Difficulty is a property of the chain, not a node setting: every node derives the same
number from the same blocks, which is what makes a block's claimed difficulty checkable.

- Every `RETARGET_INTERVAL` (10) blocks, the wall-clock span of the window that just
  closed is compared against `TARGET_BLOCK_TIME_SECS` (60) per block interval
- Blocks arriving more than 2x too fast raise the difficulty one step; more than 2x too
  slow lowers it one step; in between, a block inherits its parent's difficulty
- One step is one leading hex zero, i.e. a factor of 16 in work, that quantisation is
  the per-retarget clamp, and it is stricter than Bitcoin's 4x limit
- Difficulty is held within `MIN_DIFFICULTY` (1) and `MAX_DIFFICULTY` (32)
- The genesis block is excluded from every window: its timestamp is a fixed constant
  chosen so all nodes agree on it, not a mining time

Each block records the difficulty it was mined at, and that value is part of the hash
preimage, so it cannot be relabelled after the fact. Block acceptance re-derives the
required difficulty from the chain and rejects any block whose claim does not match,
the claim is never simply trusted.

### Consensus

Nodes follow the **longest chain rule**:
- The longest *valid* chain wins, and it must share our genesis block
- Every block of an incoming chain is re-validated (proof-of-work at the difficulty the
  retarget rules demand, signatures, balances) before it is adopted
- Forks are resolved by chain length. Since difficulty now varies, length is only a
  proxy for accumulated work; a most-work fork choice is the natural follow-up
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
├── tests/
│   └── properties.rs    # Property-based tests over the consensus invariants
├── benches/
│   └── core.rs          # Criterion benchmarks (hashing, signatures, Merkle, mining)
└── fuzz/
    ├── fuzz_targets/    # cargo-fuzz targets for every untrusted decode path
    └── seeds/           # Checked-in seed corpora
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

`benches/core.rs` is a [Criterion](https://github.com/bheisler/criterion.rs) suite over the
four costs that decide how a node behaves: header hashing, signature verification, Merkle
tree construction, and proof-of-work.

```bash
cargo bench                       # the whole suite (~4 minutes)
cargo bench -- merkle             # one group
cargo bench --no-run              # compile only
```

The figures below are the medians Criterion reported on **one** machine, an Apple M4,
macOS 26.6, `rustc` 1.94.0 stable, release profile with LTO, single-threaded. They are
illustrative: treat the ratios as the durable part and re-run `cargo bench` for your own
hardware.

| Operation | Median | Throughput |
|-----------|--------|------------|
| Block header hash (`calculate_hash`) | 436 ns | 2.29 M hashes/s |
| Proof-of-work attempt (nonce + hash) | 435 ns | 2.30 M attempts/s |
| Transaction signature verify (ed25519) | 21.9 µs | 45.6 K tx/s |
| Transaction create + sign | 17.7 µs | 56.6 K tx/s |
| Transaction hash | 991 ns | 1.01 M tx/s |
| Merkle build, 10 leaves | 7.96 µs | 1.26 M leaves/s |
| Merkle build, 1,000 leaves | 634 µs | 1.58 M leaves/s |
| Merkle build, 10,000 leaves | 6.28 ms | 1.59 M leaves/s |
| Block construction, 256 transactions | 461 µs | 555 K tx/s |
| Block `verify_transactions`, 256 transactions | 6.15 ms | 41.6 K tx/s |
| Mining, difficulty 1 | 6.64 µs |, |
| Mining, difficulty 2 | 119 µs |, |
| Mining, difficulty 3 | 1.75 ms |, |
| Mining, difficulty 4 | 28.7 ms |, |

Three things the numbers say:

- **Verification, not hashing, is what bounds a node.** A signature check costs ~50 block
  hashes, so validating a block is dominated by its transactions: `verify_transactions` over
  256 payments takes 6.15 ms, and rebuilding the Merkle root over the same 256 transactions
  is 461 µs of it, under 8%.
- **Merkle construction is linear**, holding ~1.6 M leaves/s from 100 leaves to 10,000; the
  smaller sizes are slower per leaf only because the fixed cost of the tree is not yet
  amortised.
- **Difficulty is measured, not guessed.** Each mining benchmark averages over a pool of
  distinct headers, since one block is a single draw from a geometric distribution. The
  measured times track the expected 16^d attempts (difficulty 4 ≈ 66,000 attempts at
  435 ns), so the attempt rate extrapolates: difficulty 8 is ~4.3 billion attempts, about
  31 minutes single-threaded on this machine.

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
