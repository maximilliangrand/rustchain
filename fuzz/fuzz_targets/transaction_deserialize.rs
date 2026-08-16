//! Fuzz a transaction arriving from a peer or from disk.
//!
//! A transaction is decoded before anything is known about it, so every
//! accessor a node reaches for next, hashing it for the Merkle tree, checking
//! its signature, runs on attacker-chosen fields. None of them may panic.

#![no_main]

use libfuzzer_sys::fuzz_target;
use rustchain::core::Transaction;

fuzz_target!(|data: &[u8]| {
    let Ok(tx) = serde_json::from_slice::<Transaction>(data) else {
        return;
    };

    // The hash goes into a Merkle tree before the transaction is trusted.
    let _ = tx.hash();
    // Signature verification is the first thing that touches attacker bytes:
    // hex of any length, a key that is not on the curve, a missing signature.
    let _ = tx.verify();
    let _ = tx.is_coinbase();

    // Re-encoding must not panic either, a node relays what it received.
    let _ = serde_json::to_vec(&tx);
});
