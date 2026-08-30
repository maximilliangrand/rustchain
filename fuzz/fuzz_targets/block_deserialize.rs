//! Fuzz a block arriving from a peer.
//!
//! `Message::NewBlock` hands a fully attacker-controlled block straight to
//! validation, so hashing, proof-of-work checking and transaction verification
//! all have to survive arbitrary field values.

#![no_main]

use libfuzzer_sys::fuzz_target;
use rustchain::core::blockchain::MAX_DIFFICULTY;
use rustchain::core::Block;

fuzz_target!(|data: &[u8]| {
    let Ok(block) = serde_json::from_slice::<Block>(data) else {
        return;
    };

    let _ = block.calculate_hash();
    let _ = block.verify_hash(None);

    // The claimed difficulty is a `usize` on the wire, and `verify_hash`
    // materialises a target string of that length. Chain validation never
    // reaches it with an unclamped value, `check_block_structure` compares the
    // claim against the retargeted difficulty (at most `MAX_DIFFICULTY`) and
    // bails first, so the harness clamps too rather than reporting an
    // allocation no caller can trigger.
    let _ = block.verify_hash(Some(block.difficulty.min(MAX_DIFFICULTY)));

    let _ = block.verify_transactions();
    let _ = block.total_value();
    let _ = block.mining_reward();
    let _ = block.transaction_count();

    let _ = serde_json::to_vec(&block);
});
