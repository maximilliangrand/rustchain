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
  - An account-balance ledger, derived from the chain rather than stored
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

### Multi-Node Reconvergence

`tests/reconvergence.rs` runs the network as a network. It starts two or three
real nodes on loopback ports the OS hands out, lets them mine competing forks in
isolation, then wires them together through the actual listener and the actual
length-prefixed framing, no mocks and no fixed ports. The assertions are the
ones a distributed system has to meet: every node ends on the same tip hash at
the same height, the heaviest chain wins whichever direction it arrives from, a
node handed a block it cannot attach pulls the history behind it, and a block
relays across a line of nodes to one the miner has never heard of.

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

### Canonical Hashing

Everything this chain hashes or signs is encoded the same way, by
`core::hashing::CanonicalEncoding`: a domain tag first, then each field as an 8-byte
big-endian length followed by exactly that many bytes.

```
encoding := field*
field    := u64 length (big-endian) || `length` bytes
```

The length prefix is what makes a hash a function of the *fields* rather than of the string
they were pasted into. Joined with a separator, the payment `("a|b" -> "c")` and the payment
`("a" -> "b|c")` are the same bytes: one hash, and one signature, covering two different
transfers. The domain tag keeps a preimage built in one context, a block header, from ever
being a valid preimage in another, a signature, and is where a network id would go.

Six preimages use it: the transaction hash, the transaction signing payload, the block
header, and the Merkle leaf, internal node and padding sentinel. See
[`docs/THREAT-MODEL.md`](docs/THREAT-MODEL.md) §8.

### Proof of Work

Mining finds a nonce such that the canonical encoding of the block header, index,
timestamp, Merkle root, previous hash, difficulty and nonce, hashes below the target:
```
SHA256(canonical_header(nonce)) < target
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
├── SECURITY.md          # Disclosure policy
├── docs/
│   └── THREAT-MODEL.md  # Attack surface, and what is not yet defended
├── src/
│   ├── main.rs          # CLI entry point
│   ├── lib.rs           # Library exports
│   ├── core/
│   │   ├── mod.rs       # Core module
│   │   ├── transaction.rs  # Transaction structure
│   │   ├── block.rs     # Block structure
│   │   ├── merkle.rs    # Merkle tree implementation
│   │   ├── hashing.rs   # Canonical encoding for every preimage
│   │   └── blockchain.rs   # Blockchain logic
│   ├── wallet/
│   │   └── mod.rs       # Wallet & key management
│   ├── network/
│   │   └── mod.rs       # P2P networking
│   └── cli/
│       └── mod.rs       # Command-line interface
├── tests/
│   ├── properties.rs    # Property-based tests over the consensus invariants
│   └── reconvergence.rs # Multi-node fork resolution over real TCP sockets
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

- **A Production Signature Scheme**: Signatures here are real ed25519; `secp256k1` ECDSA is what Bitcoin and Ethereum tooling expects
- **Persistent Storage**: Use a database (LevelDB, RocksDB) instead of JSON files
- **A UTXO Model**: This chain keeps one balance per address; a UTXO set would track unspent outputs instead
- **Script System**: Add programmable transaction validation (like Bitcoin Script)
- **Network Security**: Add encryption, authentication, DoS protection
- **Consensus Upgrades**: Consider PoS, PBFT, or other modern consensus mechanisms
- **Light Clients**: SPV verification for mobile/lightweight nodes

## Security

[`docs/THREAT-MODEL.md`](docs/THREAT-MODEL.md) enumerates the attack surface of *this*
design, double-spend, majority hashpower, eclipse and Sybil attacks on the peer layer, DoS
through malformed or oversized messages, timestamp manipulation, replay, signature
malleability and hash ambiguity, and says for each one what the code does, or admits that it
does nothing. The four largest open gaps are length-based fork choice, an unauthenticated and
unbounded peer table, an unpriced mempool, and plaintext key files.

[`SECURITY.md`](SECURITY.md) is the disclosure policy.

## Performance

`benches/core.rs` is a [Criterion](https://github.com/bheisler/criterion.rs) suite over the
four costs that decide how a node behaves: header hashing, signature verification, Merkle
tree construction, and proof-of-work.

```bash
cargo bench                       # the whole suite (~4 minutes)
cargo bench -- merkle             # one group
cargo bench --no-run              # compile only
```

The figures below are the point estimates Criterion reported on **one** machine, an Apple M4,
macOS 26.6, `rustc` 1.94.0 stable, release profile with LTO, single-threaded. They are
illustrative: treat the ratios as the durable part and re-run `cargo bench` for your own
hardware.

| Operation | Point estimate | Throughput |
|-----------|----------------|------------|
| Block header hash (`calculate_hash`) | 538 ns | 1.86 M hashes/s |
| Proof-of-work attempt (nonce + hash) | 537 ns | 1.86 M attempts/s |
| Transaction signature verify (ed25519, strict) | 24.2 µs | 41.3 K tx/s |
| Transaction create + sign | 17.7 µs | 56.5 K tx/s |
| Transaction hash | 958 ns | 1.04 M tx/s |
| Merkle build, 10 leaves | 7.36 µs | 1.36 M leaves/s |
| Merkle build, 1,000 leaves | 637 µs | 1.57 M leaves/s |
| Merkle build, 10,000 leaves | 6.35 ms | 1.57 M leaves/s |
| Block construction, 256 transactions | 451 µs | 568 K tx/s |
| Block `verify_transactions`, 256 transactions | 6.88 ms | 37.2 K tx/s |
| Mining, difficulty 1 | 9.49 µs |, |
| Mining, difficulty 2 | 156 µs |, |
| Mining, difficulty 3 | 2.14 ms |, |
| Mining, difficulty 4 | 37.5 ms |, |

Four things the numbers say:

- **Verification, not hashing, is what bounds a node.** A signature check costs ~45 block
  hashes, so validating a block is dominated by its transactions: `verify_transactions` over
  256 payments takes 6.88 ms, and rebuilding the Merkle root over the same 256 transactions
  is 451 µs of it, under 7%.
- **Merkle construction is linear**, holding ~1.55 M leaves/s from 100 leaves to 10,000; the
  smaller sizes are slower per leaf only because the fixed cost of the tree is not yet
  amortised.
- **Difficulty is measured, not guessed.** Each mining benchmark averages over a pool of
  distinct headers, since one block is a single draw from a geometric distribution. The
  measured times track the expected 16^d attempts (difficulty 4 ≈ 66,000 attempts at
  537 ns is ~35 ms, against 37.5 ms measured), so the attempt rate extrapolates: difficulty 8
  is ~4.3 billion attempts, about 38 minutes single-threaded on this machine.
- **Correctness costs something, and it is cheap.** Re-running the suite against the previous
  numbers, the canonical encoding made the header hash 23% slower (436 → 538 ns; the
  transaction hash got 4% *faster*, since it no longer formats a timestamp into a string),
  and `verify_strict` costs 10% over `verify` (21.9 → 24.2 µs). Merkle construction is
  unchanged. A quarter of the hash rate is the price of a preimage that cannot be re-split
  and a signature rule two implementations cannot disagree about.

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
