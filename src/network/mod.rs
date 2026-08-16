//! Network module - P2P networking for blockchain nodes
//!
//! This module provides:
//! - Node discovery and connection
//! - Block and transaction propagation
//! - Chain synchronization
//! - Consensus (longest chain rule)

use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{RwLock, Semaphore};

use crate::core::{Block, Blockchain, Transaction};

/// Default P2P port
pub const DEFAULT_PORT: u16 = 8333;

/// Maximum message size (8MB) to prevent denial-of-service via oversized messages.
///
/// Enforced against the length prefix *before* any payload is allocated, so an
/// oversized message costs us four bytes rather than its own size.
const MAX_MESSAGE_SIZE: usize = 8 * 1024 * 1024; // 8MB

/// Maximum number of transactions per block
const MAX_TXS_PER_BLOCK: usize = 1000;

/// Maximum number of simultaneous inbound connections
const MAX_INBOUND_CONNECTIONS: usize = 64;

/// How long a connection may sit idle before it is dropped
const IDLE_TIMEOUT: Duration = Duration::from_secs(120);

/// How long to wait for a peer to answer a request we made
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Result type for the framed wire protocol
pub type WireResult<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

/// Write one length-prefixed message: a 4-byte big-endian length, then JSON.
///
/// TCP is a byte stream, not a message stream: without a frame header a message
/// split across segments, or two messages in one segment, cannot be recovered.
pub async fn write_message<W>(writer: &mut W, message: &Message) -> WireResult<()>
where
    W: AsyncWriteExt + Unpin,
{
    let payload = serde_json::to_vec(message)?;

    if payload.len() > MAX_MESSAGE_SIZE {
        return Err(format!(
            "message of {} bytes exceeds the {} byte limit",
            payload.len(),
            MAX_MESSAGE_SIZE
        )
        .into());
    }

    writer
        .write_all(&(payload.len() as u32).to_be_bytes())
        .await?;
    writer.write_all(&payload).await?;
    writer.flush().await?;

    Ok(())
}

/// Read one length-prefixed message, or `None` at a clean end of stream.
pub async fn read_message<R>(reader: &mut R) -> WireResult<Option<Message>>
where
    R: AsyncReadExt + Unpin,
{
    let mut length_bytes = [0u8; 4];
    match reader.read_exact(&mut length_bytes).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e.into()),
    }

    let length = u32::from_be_bytes(length_bytes) as usize;
    if length > MAX_MESSAGE_SIZE {
        return Err(format!(
            "announced message of {} bytes exceeds the {} byte limit",
            length, MAX_MESSAGE_SIZE
        )
        .into());
    }

    let mut payload = vec![0u8; length];
    reader.read_exact(&mut payload).await?;

    Ok(Some(serde_json::from_slice(&payload)?))
}

/// Network message types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Message {
    /// Request the latest block
    GetLatestBlock,
    /// Response with the latest block
    LatestBlock(Block),
    /// Request the full blockchain
    GetBlockchain,
    /// Response with the full blockchain
    FullBlockchain(Vec<Block>),
    /// Broadcast a new block
    NewBlock(Block),
    /// Broadcast a new transaction
    NewTransaction(Transaction),
    /// Request peer list
    GetPeers,
    /// Response with peer list
    Peers(Vec<String>),
    /// Ping to check liveness
    Ping,
    /// Pong response
    Pong,
    /// Node version/handshake.
    ///
    /// `listen_address` is the address the sender accepts connections on, the
    /// socket's remote address is an ephemeral port nobody can dial back, so an
    /// inbound peer can be recorded and propagation works in both directions.
    Version {
        /// The sender's crate version.
        version: String,
        /// The height of the sender's chain, so a peer can tell who is behind.
        height: u64,
        /// The address the sender accepts connections on.
        listen_address: String,
    },
}

/// Represents a P2P node in the network
pub struct Node {
    /// The local blockchain
    pub blockchain: Arc<RwLock<Blockchain>>,
    /// Connected peer addresses
    pub peers: Arc<RwLock<HashSet<String>>>,
    /// Node listening address
    pub address: String,
    /// Node port
    pub port: u16,
    /// Where to persist the chain when it changes, if anywhere
    storage_path: Option<Arc<PathBuf>>,
}

impl Node {
    /// Create a new node
    ///
    /// # Arguments
    /// * `blockchain` - The blockchain instance
    /// * `port` - Port to listen on
    pub fn new(blockchain: Blockchain, port: u16) -> Self {
        Self {
            blockchain: Arc::new(RwLock::new(blockchain)),
            peers: Arc::new(RwLock::new(HashSet::new())),
            address: format!("127.0.0.1:{}", port),
            port,
            storage_path: None,
        }
    }

    /// Persist the chain to `path` whenever the network changes it.
    ///
    /// Without this a node forgets every block it received the moment it exits.
    pub fn with_storage(mut self, path: PathBuf) -> Self {
        self.storage_path = Some(Arc::new(path));
        self
    }

    /// Bind the listening socket and learn the address the node actually got.
    ///
    /// [`Self::start`] binds and serves in a single call, which leaves a caller
    /// that asked for port 0 no way to discover the port the OS handed out,
    /// and worse, it would keep advertising `:0` in its handshake, telling
    /// every peer to dial an address that does not exist. Binding as its own
    /// step closes both: the node's address is rewritten to the bound one
    /// before anything can quote it, and the returned listener is already
    /// accepting, so a caller knows the node is reachable without polling.
    pub async fn bind(&mut self) -> WireResult<TcpListener> {
        let listener = TcpListener::bind(&self.address).await?;
        let bound = listener.local_addr()?;

        self.address = bound.to_string();
        self.port = bound.port();

        Ok(listener)
    }

    /// Start the node server
    pub async fn start(&self) -> WireResult<()> {
        let listener = TcpListener::bind(&self.address).await?;
        self.serve(listener).await
    }

    /// Serve connections on a listener that is already bound.
    ///
    /// Runs until the future is dropped; it has no other exit.
    pub async fn serve(&self, listener: TcpListener) -> WireResult<()> {
        log::info!("Node listening on {}", self.address);

        let connection_slots = Arc::new(Semaphore::new(MAX_INBOUND_CONNECTIONS));
        let listen_address = Arc::new(self.address.clone());

        loop {
            // A failed accept is one lost client, not the end of the server: an
            // out-of-descriptors moment used to kill the listener for good.
            let (socket, addr) = match listener.accept().await {
                Ok(connection) => connection,
                Err(e) => {
                    log::warn!("Failed to accept connection: {}", e);
                    continue;
                }
            };

            let Ok(permit) = Arc::clone(&connection_slots).try_acquire_owned() else {
                log::warn!(
                    "Refusing connection from {}: {} connections already open",
                    addr,
                    MAX_INBOUND_CONNECTIONS
                );
                continue;
            };

            log::info!("New connection from {}", addr);

            let blockchain = Arc::clone(&self.blockchain);
            let peers = Arc::clone(&self.peers);
            let storage_path = self.storage_path.clone();
            let listen_address = Arc::clone(&listen_address);

            tokio::spawn(async move {
                let _permit = permit;
                if let Err(e) =
                    Self::handle_connection(socket, blockchain, peers, storage_path, listen_address)
                        .await
                {
                    log::error!("Connection error: {}", e);
                }
            });
        }
    }

    /// Handle an incoming connection
    async fn handle_connection(
        mut socket: TcpStream,
        blockchain: Arc<RwLock<Blockchain>>,
        peers: Arc<RwLock<HashSet<String>>>,
        storage_path: Option<Arc<PathBuf>>,
        local_address: Arc<String>,
    ) -> WireResult<()> {
        loop {
            let message = match tokio::time::timeout(IDLE_TIMEOUT, read_message(&mut socket)).await
            {
                Err(_) => {
                    log::info!("Closing idle connection");
                    break;
                }
                Ok(Ok(Some(message))) => message,
                Ok(Ok(None)) => break,
                Ok(Err(e)) => {
                    // Framing makes a bad message unrecoverable for this stream,
                    // so the peer is dropped rather than resynchronised.
                    log::warn!("Dropping peer after a malformed message: {}", e);
                    break;
                }
            };

            // Validate transaction count for blocks
            match &message {
                Message::NewBlock(block) if block.transactions.len() > MAX_TXS_PER_BLOCK => {
                    log::warn!(
                        "Block contains too many transactions ({} > {}), rejecting",
                        block.transactions.len(),
                        MAX_TXS_PER_BLOCK
                    );
                    continue;
                }
                _ => {}
            }

            let response =
                Self::handle_message(message, &blockchain, &peers, &storage_path, &local_address)
                    .await;

            if let Some(resp) = response {
                write_message(&mut socket, &resp).await?;
            }
        }

        Ok(())
    }

    /// Process incoming message and generate response
    async fn handle_message(
        message: Message,
        blockchain: &Arc<RwLock<Blockchain>>,
        peers: &Arc<RwLock<HashSet<String>>>,
        storage_path: &Option<Arc<PathBuf>>,
        local_address: &str,
    ) -> Option<Message> {
        match message {
            Message::GetLatestBlock => {
                let bc = blockchain.read().await;
                // A node with no chain simply has nothing to answer with; the
                // peer gets silence rather than a crash.
                bc.latest_block().cloned().map(Message::LatestBlock)
            }

            Message::GetBlockchain => {
                let bc = blockchain.read().await;
                Some(Message::FullBlockchain(bc.chain.clone()))
            }

            Message::NewBlock(block) => {
                let (accepted, orphaned) = {
                    let mut bc = blockchain.write().await;
                    match bc.add_block(block.clone()) {
                        Ok(()) => {
                            log::info!("Added new block {} from network", block.index);
                            (true, false)
                        }
                        Err(e) => {
                            log::warn!("Failed to add received block: {}", e);
                            // A block at or beyond our own tip that will not
                            // attach is the signal that this node is on the
                            // losing side of a fork: the history the block
                            // needs is history we do not have, and the block
                            // alone carries no way to get it.
                            (false, block.index as usize >= bc.len())
                        }
                    }
                };

                if accepted {
                    Self::persist(blockchain, storage_path).await;
                    Self::broadcast_to_peers(peers, Message::NewBlock(block)).await;
                } else if orphaned {
                    Self::reconverge(blockchain, peers, storage_path, local_address).await;
                }
                None
            }

            Message::NewTransaction(tx) => {
                let accepted = {
                    let mut bc = blockchain.write().await;
                    match bc.add_transaction(tx.clone()) {
                        Ok(()) => {
                            log::info!("Added new transaction {} from network", tx.id);
                            true
                        }
                        Err(e) => {
                            log::warn!("Failed to add received transaction: {}", e);
                            false
                        }
                    }
                };

                if accepted {
                    Self::persist(blockchain, storage_path).await;
                    Self::broadcast_to_peers(peers, Message::NewTransaction(tx)).await;
                }
                None
            }

            Message::GetPeers => {
                let peer_list = peers.read().await;
                Some(Message::Peers(peer_list.iter().cloned().collect()))
            }

            Message::Ping => Some(Message::Pong),

            Message::Version {
                version,
                height,
                listen_address,
            } => {
                log::info!(
                    "Peer version: {}, height: {}, listening on {}",
                    version,
                    height,
                    listen_address
                );

                // Remember the peer, otherwise propagation is one-way: we would
                // only ever push to peers named on our own command line.
                peers.write().await.insert(listen_address);

                // A peer that announces a longer chain is a fork to resolve
                // now, not whenever somebody next mines: a node joining a
                // running network has to converge on contact, and the dialling
                // side cannot do this for us, it only learns our height from
                // the reply we are about to send.
                let behind = blockchain.read().await.len() < height as usize;
                if behind {
                    Self::reconverge(blockchain, peers, storage_path, local_address).await;
                }

                let bc = blockchain.read().await;
                Some(Message::Version {
                    version: env!("CARGO_PKG_VERSION").to_string(),
                    height: bc.len() as u64,
                    listen_address: local_address.to_string(),
                })
            }

            _ => None,
        }
    }

    /// Write the chain to disk, if this node was given somewhere to write it
    async fn persist(blockchain: &Arc<RwLock<Blockchain>>, storage_path: &Option<Arc<PathBuf>>) {
        let Some(path) = storage_path else {
            return;
        };

        let json = { blockchain.read().await.to_json() };
        match json {
            Ok(json) => {
                if let Err(e) = tokio::fs::write(path.as_ref(), json).await {
                    log::error!("Failed to persist blockchain to {}: {}", path.display(), e);
                }
            }
            Err(e) => log::error!("Failed to serialize blockchain: {}", e),
        }
    }

    /// Ask one peer for its full chain over a fresh connection.
    ///
    /// `Ok(None)` means the peer answered something other than a chain, which
    /// is its right, only a transport or framing failure is an error.
    async fn request_chain(peer: &str) -> WireResult<Option<Vec<Block>>> {
        let mut socket = TcpStream::connect(peer).await?;
        write_message(&mut socket, &Message::GetBlockchain).await?;

        // A peer that accepts the request and then says nothing must not pin
        // this task forever: the caller may be holding up a handshake.
        match tokio::time::timeout(REQUEST_TIMEOUT, read_message(&mut socket)).await {
            Ok(Ok(Some(Message::FullBlockchain(chain)))) => Ok(Some(chain)),
            Ok(Ok(_)) => Ok(None),
            Ok(Err(e)) => Err(e),
            Err(_) => Err(format!("peer {} did not answer in time", peer).into()),
        }
    }

    /// Pull every known peer's chain and adopt the heaviest valid one.
    ///
    /// Reconvergence needs a pull as well as a push. Broadcasting a block tells
    /// a peer that a better chain exists but not what is in it, so a node that
    /// forked more than one block back can never catch up on gossip alone. This
    /// closes the gap, and [`Blockchain::replace_chain`], not this function,
    /// decides: a candidate is adopted only if it is longer, rooted in our own
    /// genesis, and valid block for block.
    async fn reconverge(
        blockchain: &Arc<RwLock<Blockchain>>,
        peers: &Arc<RwLock<HashSet<String>>>,
        storage_path: &Option<Arc<PathBuf>>,
        local_address: &str,
    ) {
        let targets: Vec<String> = {
            let peer_list = peers.read().await;
            peer_list
                .iter()
                .filter(|peer| peer.as_str() != local_address)
                .cloned()
                .collect()
        };

        for peer in targets {
            let offered = match Self::request_chain(&peer).await {
                Ok(Some(chain)) => chain,
                Ok(None) => continue,
                Err(e) => {
                    log::warn!("Failed to fetch the chain of peer {}: {}", peer, e);
                    continue;
                }
            };

            // The whole chain is in hand before the write lock is taken: a peer
            // that stalls mid-transfer must not freeze this node's own mining.
            let adopted = {
                let mut bc = blockchain.write().await;
                if offered.len() <= bc.len() {
                    false
                } else {
                    let offered_len = offered.len();
                    match bc.replace_chain(offered) {
                        Ok(()) => {
                            log::info!(
                                "Reconverged on the chain of peer {} ({} blocks)",
                                peer,
                                offered_len
                            );
                            true
                        }
                        Err(e) => {
                            log::warn!("Refused the chain offered by {}: {}", peer, e);
                            false
                        }
                    }
                }
            };

            if adopted {
                Self::persist(blockchain, storage_path).await;
            }
        }
    }

    /// Send a message to every known peer.
    ///
    /// The peer set is snapshotted and the lock released before any connect, and
    /// each peer is dialled in its own task: holding the lock across a TCP
    /// connect let one unreachable peer stall the whole node.
    async fn broadcast_to_peers(peers: &Arc<RwLock<HashSet<String>>>, message: Message) {
        let targets: Vec<String> = {
            let peer_list = peers.read().await;
            peer_list.iter().cloned().collect()
        };

        for peer in targets {
            let message = message.clone();
            tokio::spawn(async move {
                match TcpStream::connect(&peer).await {
                    Ok(mut socket) => {
                        if let Err(e) = write_message(&mut socket, &message).await {
                            log::warn!("Failed to send to peer {}: {}", peer, e);
                        }
                    }
                    Err(e) => log::warn!("Failed to reach peer {}: {}", peer, e),
                }
            });
        }
    }

    /// The handshake this node announces itself with
    async fn version_message(&self) -> Message {
        let bc = self.blockchain.read().await;
        Message::Version {
            version: env!("CARGO_PKG_VERSION").to_string(),
            height: bc.len() as u64,
            listen_address: self.address.clone(),
        }
    }

    /// Connect to a peer
    pub async fn connect_to_peer(&self, peer_addr: &str) -> WireResult<()> {
        let mut socket = TcpStream::connect(peer_addr).await?;

        // Send version message
        let version_msg = self.version_message().await;
        write_message(&mut socket, &version_msg).await?;
        let their_version = read_message(&mut socket).await?;

        // Add to peers
        self.peers.write().await.insert(peer_addr.to_string());
        log::info!("Connected to peer: {}", peer_addr);

        // Learn about the peer's peers
        write_message(&mut socket, &Message::GetPeers).await?;
        if let Some(Message::Peers(known)) = read_message(&mut socket).await? {
            let mut peers = self.peers.write().await;
            for peer in known {
                if peer != self.address {
                    peers.insert(peer);
                }
            }
        }

        // The handshake already told us who is ahead, so a node joining a
        // running network converges here rather than waiting for the next block
        // anybody happens to mine.
        if let Some(Message::Version { height, .. }) = their_version {
            let local_height = self.blockchain.read().await.len();
            if height as usize > local_height {
                self.sync_with_peer(peer_addr).await?;
            }
        }

        Ok(())
    }

    /// Broadcast a new block to all peers
    pub async fn broadcast_block(&self, block: &Block) {
        Self::broadcast_to_peers(&self.peers, Message::NewBlock(block.clone())).await;
    }

    /// Broadcast a new transaction to all peers
    pub async fn broadcast_transaction(&self, tx: &Transaction) {
        Self::broadcast_to_peers(&self.peers, Message::NewTransaction(tx.clone())).await;
    }

    /// Synchronize blockchain with a peer
    ///
    /// The peer's chain replaces ours only if it is longer *and* valid; a
    /// shorter or malformed offer leaves this node exactly as it was.
    pub async fn sync_with_peer(&self, peer_addr: &str) -> WireResult<()> {
        let Some(chain) = Self::request_chain(peer_addr).await? else {
            return Ok(());
        };

        let replaced = {
            let mut bc = self.blockchain.write().await;
            if chain.len() > bc.len() {
                log::info!(
                    "Received longer chain ({} vs {}), replacing...",
                    chain.len(),
                    bc.len()
                );
                match bc.replace_chain(chain) {
                    Ok(()) => true,
                    Err(e) => {
                        log::error!("Failed to replace chain: {}", e);
                        false
                    }
                }
            } else {
                false
            }
        };

        if replaced {
            Self::persist(&self.blockchain, &self.storage_path).await;
        }

        Ok(())
    }
}

/// Simple client for sending messages to nodes
pub struct Client;

impl Client {
    /// Send a message to a node and get response
    pub async fn send_message(addr: &str, message: Message) -> WireResult<Option<Message>> {
        let mut socket = TcpStream::connect(addr).await?;

        write_message(&mut socket, &message).await?;

        read_message(&mut socket).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_message_serialization() {
        let msg = Message::Ping;
        let json = serde_json::to_string(&msg).unwrap();
        let restored: Message = serde_json::from_str(&json).unwrap();

        assert!(matches!(restored, Message::Ping));
    }

    #[test]
    fn test_version_message() {
        let msg = Message::Version {
            version: "0.1.0".to_string(),
            height: 100,
            listen_address: "127.0.0.1:8333".to_string(),
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("0.1.0"));
        assert!(json.contains("100"));
    }

    #[tokio::test]
    async fn framing_survives_segmentation_and_pipelining() {
        // Regression: the protocol assumed one TCP read equals one message, so
        // a message split across segments, or two messages in one segment, was
        // silently dropped. The tiny duplex buffer forces both cases.
        let (mut client, mut server) = tokio::io::duplex(8);

        let big_peer_list: Vec<String> = (0..4096).map(|i| format!("127.0.0.1:{}", i)).collect();
        let expected = big_peer_list.clone();

        let writer = tokio::spawn(async move {
            write_message(&mut client, &Message::Ping).await.unwrap();
            write_message(&mut client, &Message::Peers(big_peer_list))
                .await
                .unwrap();
        });

        let first = read_message(&mut server)
            .await
            .unwrap()
            .expect("a first message");
        assert!(matches!(first, Message::Ping));

        let second = read_message(&mut server)
            .await
            .unwrap()
            .expect("a second message");
        match second {
            Message::Peers(peers) => assert_eq!(peers, expected),
            other => panic!("expected a peer list, got {:?}", other),
        }

        writer.await.unwrap();
    }

    #[tokio::test]
    async fn end_of_stream_is_not_an_error() {
        let (client, mut server) = tokio::io::duplex(64);
        drop(client);

        assert!(read_message(&mut server).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn an_oversized_message_is_refused_before_it_is_read() {
        // The size limit is checked against the length prefix, so it can
        // actually fire, the old check compared against a read that could never
        // exceed the buffer it read into.
        let (mut client, mut server) = tokio::io::duplex(64);

        let announced = (MAX_MESSAGE_SIZE + 1) as u32;
        client.write_all(&announced.to_be_bytes()).await.unwrap();

        assert!(read_message(&mut server).await.is_err());
    }

    #[tokio::test]
    async fn a_node_answers_a_framed_ping() {
        let node = Node::new(Blockchain::with_difficulty(2), 0);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let blockchain = Arc::clone(&node.blockchain);
        let peers = Arc::clone(&node.peers);
        tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let _ = Node::handle_connection(
                socket,
                blockchain,
                peers,
                None,
                Arc::new("127.0.0.1:0".to_string()),
            )
            .await;
        });

        let response = Client::send_message(&addr.to_string(), Message::Ping)
            .await
            .unwrap();

        assert!(matches!(response, Some(Message::Pong)));
    }

    #[tokio::test]
    async fn binding_port_zero_rewrites_the_advertised_address() {
        // A node bound to an OS-chosen port has to learn the port it got:
        // otherwise it keeps announcing `:0` in its handshake and every peer
        // records an address that can never be dialled back.
        let mut node = Node::new(Blockchain::with_difficulty(2), 0);
        let listener = node.bind().await.unwrap();
        let bound = listener.local_addr().unwrap();

        assert_ne!(node.port, 0);
        assert_eq!(node.port, bound.port());
        assert_eq!(node.address, bound.to_string());

        let Message::Version { listen_address, .. } = node.version_message().await else {
            panic!("a version message");
        };
        assert_eq!(listen_address, node.address);
    }

    #[tokio::test]
    async fn a_handshake_records_the_peer() {
        // Regression: inbound peers were never recorded, so propagation could
        // only ever go one way.
        let blockchain = Arc::new(RwLock::new(Blockchain::with_difficulty(2)));
        let peers = Arc::new(RwLock::new(HashSet::new()));

        let response = Node::handle_message(
            Message::Version {
                version: "0.1.0".to_string(),
                height: 1,
                listen_address: "127.0.0.1:18444".to_string(),
            },
            &blockchain,
            &peers,
            &None,
            "127.0.0.1:18333",
        )
        .await;

        assert!(matches!(response, Some(Message::Version { .. })));
        assert!(peers.read().await.contains("127.0.0.1:18444"));
    }
}
