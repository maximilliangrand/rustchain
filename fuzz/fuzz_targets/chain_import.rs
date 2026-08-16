//! Fuzz the on-disk chain format.
//!
//! `Blockchain::from_json` is handed the contents of a file the node does not
//! control, and it runs the full validation path, genesis check, per-height
//! difficulty retargeting, proof-of-work, Merkle roots, balance replay, before
//! the chain is usable. A malformed file must be a rejected import, never a
//! downed node.

#![no_main]

use libfuzzer_sys::fuzz_target;
use rustchain::core::Blockchain;

fuzz_target!(|data: &[u8]| {
    let Ok(json) = std::str::from_utf8(data) else {
        return;
    };

    let Ok(blockchain) = Blockchain::from_json(json) else {
        return;
    };

    // An accepted chain is immediately queried and written back out.
    let _ = blockchain.is_valid();
    let _ = blockchain.total_supply();
    let _ = blockchain.total_transactions();
    let _ = blockchain.latest_block();
    let _ = blockchain.to_json();
});
