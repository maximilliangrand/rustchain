//! RustChain - A blockchain implementation from scratch in Rust
//!
//! This is the main entry point for the CLI application.

#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_in_result
)]

use std::fs;
use std::path::Path;

use anyhow::{Context, Result};
use log::{error, info};

use rustchain::cli::{Cli, Commands, TransactionCommands, WalletCommands};
use rustchain::core::Blockchain;
use rustchain::wallet::Wallet;

fn main() -> Result<()> {
    // Initialize logger
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .format_timestamp(None)
        .init();

    let cli = Cli::parse_args();

    // Set log level based on debug flag
    if cli.debug > 0 {
        log::set_max_level(match cli.debug {
            1 => log::LevelFilter::Debug,
            _ => log::LevelFilter::Trace,
        });
    }

    match cli.command {
        Commands::Init { difficulty, output } => {
            init_blockchain(difficulty, &output)?;
        }

        Commands::Wallet { action } => {
            handle_wallet_command(action)?;
        }

        Commands::Transaction { action } => {
            handle_transaction_command(action)?;
        }

        Commands::Mine {
            address,
            blockchain,
        } => {
            mine_block(&address, &blockchain)?;
        }

        Commands::Info {
            blockchain,
            verbose,
        } => {
            show_info(&blockchain, verbose)?;
        }

        Commands::Block {
            identifier,
            blockchain,
        } => {
            show_block(&identifier, &blockchain)?;
        }

        Commands::Balance {
            address,
            blockchain,
        } => {
            show_balance(&address, &blockchain)?;
        }

        Commands::Validate { blockchain } => {
            validate_chain(&blockchain)?;
        }

        Commands::Node {
            port,
            blockchain,
            peers,
        } => {
            run_node(port, &blockchain, peers)?;
        }

        Commands::Demo { difficulty } => {
            run_demo(difficulty)?;
        }
    }

    Ok(())
}

/// Truncate a string for display without ever slicing mid-character.
///
/// Chain data is untrusted input, a short or non-ASCII address must not panic
/// the CLI.
fn short(value: &str, chars: usize) -> &str {
    match value.char_indices().nth(chars) {
        Some((byte_index, _)) => &value[..byte_index],
        None => value,
    }
}

/// Initialize a new blockchain
fn init_blockchain(difficulty: usize, output: &Path) -> Result<()> {
    info!(
        "Initializing new blockchain with difficulty {}...",
        difficulty
    );

    let blockchain = Blockchain::with_difficulty(difficulty);

    let json = blockchain.to_json()?;
    fs::write(output, json)?;

    let genesis = blockchain
        .latest_block()
        .context("a freshly initialized blockchain has a genesis block")?;

    println!("✓ Blockchain initialized!");
    println!("  Genesis block hash: {}", genesis.hash);
    println!("  Difficulty: {}", difficulty);
    println!("  Saved to: {}", output.display());

    Ok(())
}

/// Handle wallet subcommands
fn handle_wallet_command(action: WalletCommands) -> Result<()> {
    match action {
        WalletCommands::Create { output } => {
            let wallet = Wallet::new();

            println!("✓ New wallet created!");
            println!("  Address: {}", wallet.address);
            println!("  Public Key: {}", wallet.public_key);

            if let Some(path) = output {
                let json = wallet.to_json()?;
                fs::write(&path, json)?;
                println!("  Saved to: {}", path.display());
                println!("\n⚠️  Keep your wallet file secure! It contains your private key.");
            } else {
                println!("\n  Wallet JSON:");
                println!("{}", wallet.to_json()?);
            }
        }

        WalletCommands::Show { file } => {
            let json = fs::read_to_string(&file)
                .context(format!("Failed to read wallet file: {}", file.display()))?;
            let wallet = Wallet::from_json(&json)?;

            println!("Wallet Details:");
            println!("  Address: {}", wallet.address);
            println!("  Public Key: {}", wallet.public_key);
        }

        WalletCommands::Import { key, output } => {
            let wallet = Wallet::from_private_key(&key).context("Failed to import wallet")?;

            println!("✓ Wallet imported!");
            println!("  Address: {}", wallet.address);

            if let Some(path) = output {
                let json = wallet.to_json()?;
                fs::write(&path, json)?;
                println!("  Saved to: {}", path.display());
            }
        }
    }

    Ok(())
}

/// Handle transaction subcommands
fn handle_transaction_command(action: TransactionCommands) -> Result<()> {
    match action {
        TransactionCommands::Create {
            wallet,
            to,
            amount,
            blockchain: bc_path,
        } => {
            // Load wallet
            let wallet_json = fs::read_to_string(&wallet).context("Failed to read wallet file")?;
            let wallet = Wallet::from_json(&wallet_json)?;

            // Load blockchain
            let bc_json = fs::read_to_string(&bc_path).context("Failed to read blockchain file")?;
            let mut blockchain = Blockchain::from_json(&bc_json)?;

            // Create and add transaction
            let tx = wallet.create_transaction(&to, amount)?;
            blockchain.add_transaction(tx.clone())?;

            // Save blockchain
            let updated_json = blockchain.to_json()?;
            fs::write(&bc_path, updated_json)?;

            println!("✓ Transaction created!");
            println!("  ID: {}", tx.id);
            println!("  From: {}", tx.sender);
            println!("  To: {}", tx.recipient);
            println!("  Amount: {}", tx.amount);
            println!("\n  Transaction added to mempool. Mine a block to confirm it.");
        }

        TransactionCommands::Pending {
            blockchain: bc_path,
        } => {
            let bc_json = fs::read_to_string(&bc_path).context("Failed to read blockchain file")?;
            let blockchain = Blockchain::from_json(&bc_json)?;

            if blockchain.pending_transactions.is_empty() {
                println!("No pending transactions.");
            } else {
                println!(
                    "Pending Transactions ({}):",
                    blockchain.pending_transactions.len()
                );
                for tx in &blockchain.pending_transactions {
                    println!(
                        "  {} -> {} : {} coins",
                        short(&tx.sender, 20),
                        short(&tx.recipient, 20),
                        tx.amount
                    );
                }
            }
        }

        TransactionCommands::History {
            address,
            blockchain: bc_path,
        } => {
            let bc_json = fs::read_to_string(&bc_path).context("Failed to read blockchain file")?;
            let blockchain = Blockchain::from_json(&bc_json)?;

            let txs = blockchain.get_transactions_for_address(&address);

            if txs.is_empty() {
                println!("No transactions found for address: {}", address);
            } else {
                println!("Transaction History for {}:", short(&address, 20));
                for tx in txs {
                    let direction = if tx.sender == address {
                        "SENT"
                    } else {
                        "RECEIVED"
                    };
                    let other = if tx.sender == address {
                        &tx.recipient
                    } else {
                        &tx.sender
                    };
                    println!(
                        "  {} {} coins {} {}",
                        direction,
                        tx.amount,
                        if direction == "SENT" { "to" } else { "from" },
                        short(other, 20)
                    );
                }
            }
        }
    }

    Ok(())
}

/// Mine a new block
fn mine_block(address: &str, bc_path: &Path) -> Result<()> {
    let bc_json = fs::read_to_string(bc_path).context("Failed to read blockchain file")?;
    let mut blockchain = Blockchain::from_json(&bc_json)?;

    println!("Mining new block...");
    println!("  Difficulty: {}", blockchain.difficulty);
    println!(
        "  Pending transactions: {}",
        blockchain.pending_transactions.len()
    );

    let start = std::time::Instant::now();
    let block = blockchain
        .mine_pending_transactions(address)
        .context("Mining failed - the blockchain file is unchanged")?;
    let duration = start.elapsed();

    // Save updated blockchain
    let updated_json = blockchain.to_json()?;
    fs::write(bc_path, updated_json)?;

    println!("\n✓ Block mined!");
    println!("  Index: {}", block.index);
    println!("  Hash: {}", block.hash);
    println!("  Nonce: {}", block.nonce);
    println!("  Transactions: {}", block.transaction_count());
    println!("  Time: {:?}", duration);
    println!(
        "  Mining reward: {} coins -> {}",
        blockchain.mining_reward, address
    );

    Ok(())
}

/// Show blockchain information
fn show_info(bc_path: &Path, verbose: bool) -> Result<()> {
    let bc_json = fs::read_to_string(bc_path).context("Failed to read blockchain file")?;
    let blockchain = Blockchain::from_json(&bc_json)?;

    println!("═══════════════════════════════════════════════════════════════");
    println!("                      BLOCKCHAIN INFO");
    println!("═══════════════════════════════════════════════════════════════");
    println!("  Chain length:        {} blocks", blockchain.len());
    println!("  Difficulty:          {}", blockchain.difficulty);
    println!("  Total transactions:  {}", blockchain.total_transactions());
    println!("  Total supply:        {} coins", blockchain.total_supply());
    println!(
        "  Pending tx:          {}",
        blockchain.pending_transactions.len()
    );
    println!("───────────────────────────────────────────────────────────────");
    println!("  Latest block:");
    match blockchain.latest_block() {
        Some(latest) => {
            println!("    Index:  {}", latest.index);
            println!("    Hash:   {}", latest.hash);
            println!("    Time:   {}", latest.timestamp);
        }
        None => println!("    (none - the chain is empty)"),
    }
    println!("═══════════════════════════════════════════════════════════════");

    if verbose {
        println!("\nAll Blocks:");
        for block in &blockchain.chain {
            println!("\n  Block #{}", block.index);
            println!("    Hash:       {}", block.hash);
            println!("    Prev Hash:  {}...", short(&block.previous_hash, 16));
            println!("    Merkle:     {}...", short(&block.merkle_root, 16));
            println!("    Nonce:      {}", block.nonce);
            println!("    Tx Count:   {}", block.transaction_count());
            println!("    Timestamp:  {}", block.timestamp);
        }
    }

    Ok(())
}

/// Show a specific block
fn show_block(identifier: &str, bc_path: &Path) -> Result<()> {
    let bc_json = fs::read_to_string(bc_path).context("Failed to read blockchain file")?;
    let blockchain = Blockchain::from_json(&bc_json)?;

    let block = if let Ok(index) = identifier.parse::<u64>() {
        blockchain.get_block(index)
    } else {
        blockchain.get_block_by_hash(identifier)
    };

    match block {
        Some(block) => {
            println!("Block #{}", block.index);
            println!("═══════════════════════════════════════════════════════════════");
            println!("  Hash:         {}", block.hash);
            println!("  Previous:     {}", block.previous_hash);
            println!("  Merkle Root:  {}", block.merkle_root);
            println!("  Nonce:        {}", block.nonce);
            println!("  Timestamp:    {}", block.timestamp);
            println!("───────────────────────────────────────────────────────────────");
            println!("  Transactions ({}):", block.transaction_count());
            for tx in &block.transactions {
                if tx.is_coinbase() {
                    println!(
                        "    [COINBASE] {} coins -> {}",
                        tx.amount,
                        short(&tx.recipient, 20)
                    );
                } else {
                    println!(
                        "    {} -> {}: {} coins",
                        short(&tx.sender, 20),
                        short(&tx.recipient, 20),
                        tx.amount
                    );
                }
            }
        }
        None => {
            error!("Block not found: {}", identifier);
        }
    }

    Ok(())
}

/// Show balance of an address
fn show_balance(address: &str, bc_path: &Path) -> Result<()> {
    let bc_json = fs::read_to_string(bc_path).context("Failed to read blockchain file")?;
    let blockchain = Blockchain::from_json(&bc_json)?;

    let balance = blockchain.get_balance(address);
    println!("Balance for {}:", address);
    println!("  {} coins", balance);

    Ok(())
}

/// Validate the blockchain
fn validate_chain(bc_path: &Path) -> Result<()> {
    let bc_json = fs::read_to_string(bc_path).context("Failed to read blockchain file")?;
    let blockchain = Blockchain::from_json(&bc_json)?;

    print!("Validating blockchain... ");

    match blockchain.is_valid() {
        Ok(()) => {
            println!("✓ Valid!");
            println!("  All {} blocks verified.", blockchain.len());
        }
        Err(e) => {
            println!("✗ Invalid!");
            error!("Validation error: {}", e);
        }
    }

    Ok(())
}

/// Run a network node
fn run_node(port: u16, bc_path: &Path, peers: Vec<String>) -> Result<()> {
    let bc_json = fs::read_to_string(bc_path).context("Failed to read blockchain file")?;
    let blockchain = Blockchain::from_json(&bc_json)?;

    println!("Starting node on port {}...", port);
    println!("Blockchain height: {} blocks", blockchain.len());

    // Create runtime for async network code
    let rt = tokio::runtime::Runtime::new()?;

    rt.block_on(async {
        let node =
            rustchain::network::Node::new(blockchain, port).with_storage(bc_path.to_path_buf());

        // Connect to initial peers and adopt the longest chain they offer
        for peer in peers {
            if let Err(e) = node.connect_to_peer(&peer).await {
                error!("Failed to connect to peer {}: {}", peer, e);
                continue;
            }
            if let Err(e) = node.sync_with_peer(&peer).await {
                error!("Failed to sync with peer {}: {}", peer, e);
            }
        }

        println!(
            "Chain height after sync: {} blocks",
            node.blockchain.read().await.len()
        );

        // Start the node server
        if let Err(e) = node.start().await {
            error!("Node error: {}", e);
        }
    });

    Ok(())
}

/// Run an interactive demo
fn run_demo(difficulty: usize) -> Result<()> {
    println!("═══════════════════════════════════════════════════════════════");
    println!("              RUSTCHAIN INTERACTIVE DEMO");
    println!("═══════════════════════════════════════════════════════════════");
    println!();

    // Create blockchain
    println!("1. Creating blockchain with difficulty {}...", difficulty);
    let mut blockchain = Blockchain::with_difficulty(difficulty);
    println!("   ✓ Genesis block created");
    println!(
        "   Hash: {}",
        blockchain
            .latest_block()
            .context("a freshly created blockchain has a genesis block")?
            .hash
    );
    println!();

    // Create wallets
    println!("2. Creating wallets...");
    let alice = Wallet::new();
    let bob = Wallet::new();
    let miner = Wallet::new();
    println!("   ✓ Alice: {}", short(&alice.address, 20));
    println!("   ✓ Bob:   {}", short(&bob.address, 20));
    println!("   ✓ Miner: {}", short(&miner.address, 20));
    println!();

    // Initial balances
    println!("3. Initial balances:");
    println!(
        "   Genesis: {} coins",
        blockchain.get_balance("genesis_address")
    );
    println!(
        "   Alice:   {} coins",
        blockchain.get_balance(&alice.address)
    );
    println!("   Bob:     {} coins", blockchain.get_balance(&bob.address));
    println!(
        "   Miner:   {} coins",
        blockchain.get_balance(&miner.address)
    );
    println!();

    // Mine first block to give miner some coins
    println!("4. Mining block 1 (miner gets reward)...");
    let start = std::time::Instant::now();
    let block1 = blockchain.mine_pending_transactions(&miner.address)?;
    println!("   ✓ Block mined in {:?}", start.elapsed());
    println!("   Hash: {}...", short(&block1.hash, 32));
    println!("   Nonce: {}", block1.nonce);
    println!();

    // Create transaction
    println!("5. Creating transaction: Miner -> Alice (25 coins)...");
    let tx = miner.create_transaction(&alice.address, 25)?;
    blockchain.add_transaction(tx)?;
    println!("   ✓ Transaction added to mempool");
    println!();

    // Mine second block
    println!("6. Mining block 2 (includes transaction)...");
    let start = std::time::Instant::now();
    let block2 = blockchain.mine_pending_transactions(&miner.address)?;
    println!("   ✓ Block mined in {:?}", start.elapsed());
    println!("   Transactions in block: {}", block2.transaction_count());
    println!();

    // Create another transaction
    println!("7. Creating transaction: Alice -> Bob (10 coins)...");
    let tx2 = alice.create_transaction(&bob.address, 10)?;
    blockchain.add_transaction(tx2)?;
    println!("   ✓ Transaction added to mempool");
    println!();

    // Mine third block
    println!("8. Mining block 3...");
    let start = std::time::Instant::now();
    blockchain.mine_pending_transactions(&miner.address)?;
    println!("   ✓ Block mined in {:?}", start.elapsed());
    println!();

    // Final state
    println!("═══════════════════════════════════════════════════════════════");
    println!("                     FINAL STATE");
    println!("═══════════════════════════════════════════════════════════════");
    println!("  Chain length: {} blocks", blockchain.len());
    println!("  Total supply: {} coins", blockchain.total_supply());
    println!();
    println!("  Balances:");
    println!(
        "    Genesis: {} coins",
        blockchain.get_balance("genesis_address")
    );
    println!(
        "    Miner:   {} coins (3 block rewards - 25 sent)",
        blockchain.get_balance(&miner.address)
    );
    println!(
        "    Alice:   {} coins (25 received - 10 sent)",
        blockchain.get_balance(&alice.address)
    );
    println!(
        "    Bob:     {} coins (10 received)",
        blockchain.get_balance(&bob.address)
    );
    println!();

    // Validate
    println!("9. Validating blockchain...");
    match blockchain.is_valid() {
        Ok(()) => println!("   ✓ Blockchain is valid!"),
        Err(e) => println!("   ✗ Validation failed: {}", e),
    }
    println!();
    println!("═══════════════════════════════════════════════════════════════");
    println!("                    DEMO COMPLETE");
    println!("═══════════════════════════════════════════════════════════════");

    Ok(())
}
