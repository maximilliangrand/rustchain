//! Fuzz the JSON body of a network message.
//!
//! This is the payload half of the wire protocol: whatever bytes a peer put
//! after the length prefix, handed to serde. It reaches every variant of
//! [`Message`], including the block and transaction payloads, without paying
//! for framing on every iteration.

#![no_main]

use libfuzzer_sys::fuzz_target;
use rustchain::network::Message;

fuzz_target!(|data: &[u8]| {
    let Ok(message) = serde_json::from_slice::<Message>(data) else {
        return;
    };

    // A node inspects the message before acting on it, then relays it.
    match &message {
        Message::LatestBlock(block) | Message::NewBlock(block) => {
            let _ = block.calculate_hash();
            let _ = block.verify_transactions();
        }
        Message::FullBlockchain(chain) => {
            for block in chain {
                let _ = block.calculate_hash();
            }
        }
        Message::NewTransaction(tx) => {
            let _ = tx.hash();
            let _ = tx.verify();
        }
        Message::Version {
            version,
            height,
            listen_address,
        } => {
            let _ = (version.len(), height, listen_address.len());
        }
        Message::Peers(peers) => {
            for peer in peers {
                let _ = peer.parse::<std::net::SocketAddr>();
            }
        }
        Message::GetLatestBlock | Message::GetBlockchain | Message::GetPeers => {}
        Message::Ping | Message::Pong => {}
    }

    let _ = serde_json::to_vec(&message);
});
