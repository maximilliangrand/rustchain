//! Criterion benchmarks for the hot paths of the chain.
//!
//! Four things dominate the cost of running a node, and each gets a group here:
//! - `block_hash`, the SHA-256 of a block header, the unit of proof-of-work
//! - `transaction`, ed25519 signing and verification, the cost of accepting a payment
//! - `merkle`, building the transaction tree, which grows with the block size
//! - `mining`, the raw hash-attempt rate, and how full mining scales with difficulty
//!
//! Difficulties are kept low (1..=4) so a full run finishes in minutes; the
//! attempt rate is the figure that extrapolates to any difficulty, since the
//! expected work is `16^difficulty` attempts.

use criterion::{criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion, Throughput};
use std::hint::black_box;

use rustchain::core::{Block, MerkleTree, Transaction};
use rustchain::wallet::Wallet;

/// A signed transaction from a fresh wallet, i.e. one that actually verifies.
fn signed_transaction() -> Transaction {
    Wallet::new()
        .create_transaction("recipient_address", 100)
        .expect("a freshly generated wallet must sign")
}

/// A block carrying `count` signed transactions.
fn block_with(count: usize) -> Block {
    let transactions: Vec<Transaction> = (0..count).map(|_| signed_transaction()).collect();
    Block::new(1, transactions, "previous_hash".to_string())
}

/// Hashing a block header, and building one from its transactions.
///
/// `calculate_hash` covers the header only, the transactions reach it through
/// the Merkle root, so its cost is flat in the transaction count. `Block::new`
/// is where that count is paid: it hashes every transaction and builds the tree.
fn block_hashing(c: &mut Criterion) {
    let mut group = c.benchmark_group("block_hash");

    let block = block_with(4);
    group.throughput(Throughput::Elements(1));
    group.bench_function("calculate_hash", |b| {
        b.iter(|| black_box(&block).calculate_hash())
    });

    for count in [1usize, 16, 256] {
        let transactions: Vec<Transaction> = (0..count).map(|_| signed_transaction()).collect();

        group.throughput(Throughput::Elements(count as u64));
        group.bench_with_input(
            BenchmarkId::new("block_new", count),
            &transactions,
            |b, transactions| {
                b.iter(|| {
                    Block::new(
                        1,
                        black_box(transactions).clone(),
                        "previous_hash".to_string(),
                    )
                })
            },
        );
    }

    group.finish();
}

/// Signing and verifying transactions, the per-payment cost of ed25519.
///
/// Verification is the one a node pays for every transaction it is handed by a
/// peer, so it is the number that bounds transaction ingest.
fn transaction_verification(c: &mut Criterion) {
    let mut group = c.benchmark_group("transaction");
    group.throughput(Throughput::Elements(1));

    let transaction = signed_transaction();
    group.bench_function("verify", |b| b.iter(|| black_box(&transaction).verify()));

    group.bench_function("hash", |b| b.iter(|| black_box(&transaction).hash()));

    let wallet = Wallet::new();
    group.bench_function("sign", |b| {
        b.iter(|| {
            black_box(&wallet)
                .create_transaction("recipient_address", 100)
                .expect("a freshly generated wallet must sign")
        })
    });

    // Whole-block verification: Merkle root rebuild plus one signature check
    // per transaction. This is what `add_block` runs on every incoming block.
    for count in [1usize, 16, 256] {
        let block = block_with(count);

        group.throughput(Throughput::Elements(count as u64));
        group.bench_with_input(
            BenchmarkId::new("block_verify_transactions", count),
            &block,
            |b, block| b.iter(|| black_box(block).verify_transactions()),
        );
    }

    group.finish();
}

/// Building the Merkle tree over a block's transaction hashes.
///
/// Tree construction is O(n) hashes for n leaves, so the interesting figure is
/// throughput in leaves per second rather than wall time at any one size.
fn merkle_build(c: &mut Criterion) {
    let mut group = c.benchmark_group("merkle");

    for count in [1usize, 10, 100, 1_000, 10_000] {
        let hashes: Vec<String> = (0..count).map(|i| format!("tx_hash_{}", i)).collect();

        group.throughput(Throughput::Elements(count as u64));
        group.bench_with_input(BenchmarkId::new("build", count), &hashes, |b, hashes| {
            b.iter(|| MerkleTree::new(black_box(hashes).clone()))
        });
    }

    group.finish();
}

/// Proof-of-work: the raw attempt rate, and full mining against difficulty.
///
/// `hash_attempt` is the rate the search runs at, one nonce increment plus one
/// header hash, and it is what generalises: mining at difficulty `d` needs
/// `16^d` attempts on average, so difficulty 8 is (attempt time × 4.3e9).
/// The `difficulty/*` benchmarks measure the search end to end at difficulties
/// small enough to finish quickly.
///
/// One block has exactly one nonce search, and its length is a single draw from
/// a geometric distribution, timing the same block repeatedly would report
/// that one draw, not the expected work. Each iteration therefore takes the
/// next header out of a pool of distinct blocks, so the reported mean is an
/// average over many independent searches.
fn mining(c: &mut Criterion) {
    let mut group = c.benchmark_group("mining");

    let mut block = block_with(4);
    group.throughput(Throughput::Elements(1));
    group.bench_function("hash_attempt", |b| {
        b.iter(|| {
            block.nonce = block.nonce.wrapping_add(1);
            black_box(&block).calculate_hash()
        })
    });

    // Proof-of-work runs are long and high-variance; fewer, longer samples.
    group.sample_size(20);
    group.measurement_time(std::time::Duration::from_secs(10));

    // Distinct headers to mine: the previous hash is part of the preimage, so
    // each of these is an independent nonce search.
    let template = block_with(4);
    let headers: Vec<Block> = (0..256u32)
        .map(|i| {
            let mut block = template.clone();
            block.previous_hash = format!("previous_hash_{}", i);
            block
        })
        .collect();

    for difficulty in 1usize..=4 {
        let mut next = 0usize;

        group.throughput(Throughput::Elements(1));
        group.bench_with_input(
            BenchmarkId::new("difficulty", difficulty),
            &difficulty,
            |b, &difficulty| {
                b.iter_batched(
                    || {
                        next = (next + 1) % headers.len();
                        headers[next].clone()
                    },
                    |mut block| block.mine(difficulty),
                    BatchSize::SmallInput,
                )
            },
        );
    }

    group.finish();
}

criterion_group!(
    benches,
    block_hashing,
    transaction_verification,
    merkle_build,
    mining
);
criterion_main!(benches);
