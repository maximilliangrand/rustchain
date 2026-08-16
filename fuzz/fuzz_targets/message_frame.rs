//! Fuzz the framed wire protocol end to end.
//!
//! `read_message` is the very first code a connected peer reaches: it parses a
//! four-byte length prefix and then reads that many bytes. This target feeds it
//! a whole raw stream and drains it, so the fuzzer explores truncated frames,
//! absurd length prefixes, and several messages pipelined into one buffer.

#![no_main]

use libfuzzer_sys::fuzz_target;
use rustchain::network::read_message;

fuzz_target!(|data: &[u8]| {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("a current-thread runtime always builds");

    runtime.block_on(async {
        // `&[u8]` is an `AsyncRead` that is always ready, so the whole stream is
        // consumed without any real I/O.
        let mut stream = data;

        // Stop at the first error or clean end of stream, exactly as the
        // connection handler does.
        while let Ok(Some(message)) = read_message(&mut stream).await {
            let _ = serde_json::to_vec(&message);
        }
    });
});
