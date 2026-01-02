//! Network module - P2P networking for blockchain nodes
//!
//! This module provides:
//! - Node discovery and connection
//! - Block and transaction propagation
//! - Chain synchronization
//! - Consensus (longest chain rule)

use std::collections::HashSet;
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use serde::{Deserialize, Serialize};

use crate::core::{Block, Blockchain, Transaction};

/// Default P2P port
pub const DEFAULT_PORT: u16 = 8333;

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
    /// Node version/handshake
    Version { version: String, height: u64 },
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
        }
    }

    /// Start the node server
    pub async fn start(&self) -> Result<(), Box<dyn std::error::Error>> {
        let listener = TcpListener::bind(&self.address).await?;
        log::info!("Node listening on {}", self.address);

        loop {
            let (socket, addr) = listener.accept().await?;
            log::info!("New connection from {}", addr);

            let blockchain = Arc::clone(&self.blockchain);
            let peers = Arc::clone(&self.peers);

            tokio::spawn(async move {
                if let Err(e) = Self::handle_connection(socket, blockchain, peers).await {
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
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut buffer = vec![0u8; 65536];

        loop {
            let n = socket.read(&mut buffer).await?;
            if n == 0 {
                break;
            }

            let message: Message = serde_json::from_slice(&buffer[..n])?;
            let response = Self::handle_message(message, &blockchain, &peers).await;

            if let Some(resp) = response {
                let resp_bytes = serde_json::to_vec(&resp)?;
                socket.write_all(&resp_bytes).await?;
            }
        }

        Ok(())
    }

    /// Process incoming message and generate response
    async fn handle_message(
        message: Message,
        blockchain: &Arc<RwLock<Blockchain>>,
        peers: &Arc<RwLock<HashSet<String>>>,
    ) -> Option<Message> {
        match message {
            Message::GetLatestBlock => {
                let bc = blockchain.read().await;
                Some(Message::LatestBlock(bc.latest_block().clone()))
            }

            Message::GetBlockchain => {
                let bc = blockchain.read().await;
                Some(Message::FullBlockchain(bc.chain.clone()))
            }

            Message::NewBlock(block) => {
                let mut bc = blockchain.write().await;
                if let Err(e) = bc.add_block(block.clone()) {
                    log::warn!("Failed to add received block: {}", e);
                } else {
                    log::info!("Added new block {} from network", block.index);
                }
                None
            }

            Message::NewTransaction(tx) => {
                let mut bc = blockchain.write().await;
                if let Err(e) = bc.add_transaction(tx.clone()) {
                    log::warn!("Failed to add received transaction: {}", e);
                } else {
                    log::info!("Added new transaction {} from network", tx.id);
                }
                None
            }

            Message::GetPeers => {
                let peer_list = peers.read().await;
                Some(Message::Peers(peer_list.iter().cloned().collect()))
            }

            Message::Ping => Some(Message::Pong),

            Message::Version { version, height } => {
                log::info!("Peer version: {}, height: {}", version, height);
                let bc = blockchain.read().await;
                Some(Message::Version {
                    version: env!("CARGO_PKG_VERSION").to_string(),
                    height: bc.len() as u64,
                })
            }

            _ => None,
        }
    }

    /// Connect to a peer
    pub async fn connect_to_peer(&self, peer_addr: &str) -> Result<(), Box<dyn std::error::Error>> {
        let mut socket = TcpStream::connect(peer_addr).await?;

        // Send version message
        let bc = self.blockchain.read().await;
        let version_msg = Message::Version {
            version: env!("CARGO_PKG_VERSION").to_string(),
            height: bc.len() as u64,
        };
        drop(bc);

        let msg_bytes = serde_json::to_vec(&version_msg)?;
        socket.write_all(&msg_bytes).await?;

        // Add to peers
        self.peers.write().await.insert(peer_addr.to_string());
        log::info!("Connected to peer: {}", peer_addr);

        Ok(())
    }

    /// Broadcast a new block to all peers
    pub async fn broadcast_block(&self, block: &Block) {
        let peers = self.peers.read().await;
        let message = Message::NewBlock(block.clone());
        let msg_bytes = serde_json::to_vec(&message).unwrap();

        for peer in peers.iter() {
            if let Ok(mut socket) = TcpStream::connect(peer).await {
                let _ = socket.write_all(&msg_bytes).await;
            }
        }
    }

    /// Broadcast a new transaction to all peers
    pub async fn broadcast_transaction(&self, tx: &Transaction) {
        let peers = self.peers.read().await;
        let message = Message::NewTransaction(tx.clone());
        let msg_bytes = serde_json::to_vec(&message).unwrap();

        for peer in peers.iter() {
            if let Ok(mut socket) = TcpStream::connect(peer).await {
                let _ = socket.write_all(&msg_bytes).await;
            }
        }
    }

    /// Synchronize blockchain with a peer
    pub async fn sync_with_peer(&self, peer_addr: &str) -> Result<(), Box<dyn std::error::Error>> {
        let mut socket = TcpStream::connect(peer_addr).await?;

        // Request full blockchain
        let request = Message::GetBlockchain;
        let req_bytes = serde_json::to_vec(&request)?;
        socket.write_all(&req_bytes).await?;

        // Read response
        let mut buffer = vec![0u8; 1024 * 1024]; // 1MB buffer for blockchain
        let n = socket.read(&mut buffer).await?;

        if let Ok(Message::FullBlockchain(chain)) = serde_json::from_slice(&buffer[..n]) {
            let mut bc = self.blockchain.write().await;
            if chain.len() > bc.len() {
                log::info!(
                    "Received longer chain ({} vs {}), replacing...",
                    chain.len(),
                    bc.len()
                );
                if let Err(e) = bc.replace_chain(chain) {
                    log::error!("Failed to replace chain: {}", e);
                }
            }
        }

        Ok(())
    }
}

/// Simple client for sending messages to nodes
pub struct Client;

impl Client {
    /// Send a message to a node and get response
    pub async fn send_message(
        addr: &str,
        message: Message,
    ) -> Result<Option<Message>, Box<dyn std::error::Error>> {
        let mut socket = TcpStream::connect(addr).await?;

        let msg_bytes = serde_json::to_vec(&message)?;
        socket.write_all(&msg_bytes).await?;

        let mut buffer = vec![0u8; 65536];
        let n = socket.read(&mut buffer).await?;

        if n > 0 {
            let response: Message = serde_json::from_slice(&buffer[..n])?;
            Ok(Some(response))
        } else {
            Ok(None)
        }
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
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("0.1.0"));
        assert!(json.contains("100"));
    }
}
