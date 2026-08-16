//! CLI module - Command-line interface for the blockchain
//!
//! Provides commands for:
//! - Creating and managing wallets
//! - Sending transactions
//! - Mining blocks
//! - Viewing blockchain state
//! - Running a network node

use clap::{Parser, Subcommand};
use std::path::PathBuf;

/// RustChain - A blockchain implementation in Rust
#[derive(Parser)]
#[command(name = "rustchain")]
#[command(author = "Your Name")]
#[command(version = "0.1.0")]
#[command(about = "A blockchain implementation from scratch in Rust", long_about = None)]
pub struct Cli {
    /// Sets a custom config file
    #[arg(short, long, value_name = "FILE")]
    pub config: Option<PathBuf>,

    /// Turn debugging information on
    #[arg(short, long, action = clap::ArgAction::Count)]
    pub debug: u8,

    /// The subcommand to run
    #[command(subcommand)]
    pub command: Commands,
}

/// The top-level commands `rustchain` accepts
#[derive(Subcommand)]
pub enum Commands {
    /// Initialize a new blockchain
    Init {
        /// Starting mining difficulty (number of leading zeros); retargets from there
        #[arg(short, long, default_value = "4")]
        difficulty: usize,

        /// Output file for blockchain data
        #[arg(short, long, default_value = "blockchain.json")]
        output: PathBuf,
    },

    /// Create a new wallet
    Wallet {
        /// The wallet operation to run
        #[command(subcommand)]
        action: WalletCommands,
    },

    /// Transaction operations
    Transaction {
        /// The transaction operation to run
        #[command(subcommand)]
        action: TransactionCommands,
    },

    /// Mine a new block
    Mine {
        /// Miner wallet address
        #[arg(short, long)]
        address: String,

        /// Blockchain data file
        #[arg(short, long, default_value = "blockchain.json")]
        blockchain: PathBuf,
    },

    /// Show blockchain information
    Info {
        /// Blockchain data file
        #[arg(short, long, default_value = "blockchain.json")]
        blockchain: PathBuf,

        /// Show detailed block information
        #[arg(short, long)]
        verbose: bool,
    },

    /// Show a specific block
    Block {
        /// Block index or hash
        identifier: String,

        /// Blockchain data file
        #[arg(short, long, default_value = "blockchain.json")]
        blockchain: PathBuf,
    },

    /// Check balance of an address
    Balance {
        /// Wallet address
        address: String,

        /// Blockchain data file
        #[arg(short, long, default_value = "blockchain.json")]
        blockchain: PathBuf,
    },

    /// Validate the blockchain
    Validate {
        /// Blockchain data file
        #[arg(short, long, default_value = "blockchain.json")]
        blockchain: PathBuf,
    },

    /// Run a network node
    Node {
        /// Port to listen on
        #[arg(short, long, default_value = "8333")]
        port: u16,

        /// Blockchain data file
        #[arg(short, long, default_value = "blockchain.json")]
        blockchain: PathBuf,

        /// Peer nodes to connect to
        #[arg(long)]
        peers: Vec<String>,
    },

    /// Run interactive demo
    Demo {
        /// Mining difficulty for demo
        #[arg(short, long, default_value = "2")]
        difficulty: usize,
    },
}

/// Wallet operations: key generation, inspection and import
#[derive(Subcommand)]
pub enum WalletCommands {
    /// Create a new wallet
    Create {
        /// Output file for wallet
        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    /// Show wallet details
    Show {
        /// Wallet file
        #[arg(short, long)]
        file: PathBuf,
    },

    /// Import wallet from private key
    Import {
        /// Private key
        key: String,

        /// Output file for wallet
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
}

/// Transaction operations: creation, the mempool, and history
#[derive(Subcommand)]
pub enum TransactionCommands {
    /// Create a new transaction
    Create {
        /// Sender wallet file
        #[arg(short, long)]
        wallet: PathBuf,

        /// Recipient address
        #[arg(short, long)]
        to: String,

        /// Amount to send
        #[arg(short, long)]
        amount: u64,

        /// Blockchain data file
        #[arg(short, long, default_value = "blockchain.json")]
        blockchain: PathBuf,
    },

    /// List pending transactions
    Pending {
        /// Blockchain data file
        #[arg(short, long, default_value = "blockchain.json")]
        blockchain: PathBuf,
    },

    /// Show transaction history for an address
    History {
        /// Wallet address
        address: String,

        /// Blockchain data file
        #[arg(short, long, default_value = "blockchain.json")]
        blockchain: PathBuf,
    },
}

impl Cli {
    /// Parse command line arguments
    pub fn parse_args() -> Self {
        Cli::parse()
    }
}
