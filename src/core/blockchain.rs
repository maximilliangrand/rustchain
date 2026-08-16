//! Blockchain module - the chain of blocks with validation logic
//!
//! The blockchain maintains:
//! - The chain of blocks from genesis to tip
//! - Validation rules for new blocks
//! - An account-balance ledger: one balance per address, derived from the chain
//! - Mempool for pending transactions
//!
//! The ledger is an account model, not a UTXO set. A transaction moves an amount
//! from one address to another and the two balances are updated in place; there
//! are no outputs to spend, so there is nothing for a later transaction to point
//! at. Replay is prevented by the confirmed-transaction-id index rather than by
//! an output being consumed.

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use thiserror::Error;

use super::block::Block;
use super::transaction::Transaction;

/// Starting mining difficulty (number of leading zeros required)
pub const DEFAULT_DIFFICULTY: usize = 4;

/// How long a block is meant to take, in seconds
pub const TARGET_BLOCK_TIME_SECS: i64 = 60;

/// Number of blocks between difficulty retargets
pub const RETARGET_INTERVAL: u64 = 10;

/// Difficulty floor. At zero a block needs no proof-of-work at all, so the
/// chain would be free to rewrite.
pub const MIN_DIFFICULTY: usize = 1;

/// Difficulty ceiling. A hex hash has 64 digits, and long before that a chain
/// is unmineable; the cap keeps a runaway retarget from bricking the node.
pub const MAX_DIFFICULTY: usize = 32;

/// How far the observed timespan may miss the target before the difficulty
/// moves: twice too fast raises it, twice too slow lowers it.
const RETARGET_TOLERANCE: i64 = 2;

/// How many preceding blocks the median-time-past rule looks back over.
///
/// A block's timestamp must be strictly greater than the median of the previous
/// up to this many blocks. Bitcoin uses eleven; the same number here ties the
/// lower bound on a timestamp to real recent history instead of to a single
/// value one miner picks.
const MEDIAN_TIME_SPAN: usize = 11;

/// Mining reward
pub const MINING_REWARD: u64 = 50;

/// The genesis difficulty a deserialized chain is anchored to.
///
/// `difficulty` is `#[serde(skip)]`, so this is the value a chain loaded from an
/// untrusted file starts from, rather than whatever the file claimed.
fn genesis_difficulty() -> usize {
    DEFAULT_DIFFICULTY
}

/// Blockchain errors
#[derive(Error, Debug)]
pub enum BlockchainError {
    /// A block was refused: it broke one of the rules block acceptance
    /// enforces.
    #[error("Invalid block: {0}")]
    InvalidBlock(String),

    /// A transaction was refused, by the mempool or by block application.
    #[error("Invalid transaction: {0}")]
    InvalidTransaction(String),

    /// A sender cannot cover a spend.
    #[error("Insufficient balance: has {has}, needs {needs}")]
    InsufficientBalance {
        /// What the sender holds.
        has: u64,
        /// What the transaction would spend.
        needs: u64,
    },

    /// A whole chain was refused, by validation or by chain replacement.
    #[error("Invalid chain: {0}")]
    InvalidChain(String),

    /// No block with the requested index or hash is in the chain.
    #[error("Block not found: {0}")]
    BlockNotFound(String),

    /// No chain to build on. Only reachable through a hand-built [`Blockchain`]
    /// value: every constructor and [`Blockchain::from_json`] starts from a
    /// genesis block.
    #[error("Chain is empty")]
    EmptyChain,

    /// Stored chain data could not be parsed as a [`Blockchain`].
    #[error("Malformed blockchain data: {0}")]
    Malformed(#[from] serde_json::Error),
}

/// The main blockchain structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Blockchain {
    /// The chain of blocks
    pub chain: Vec<Block>,
    /// Difficulty the chain starts at.
    ///
    /// Only the first mined block uses it directly; from there difficulty is
    /// derived from the blocks themselves by [`Blockchain::next_difficulty`].
    ///
    /// Never read from disk. It is the network's genesis-difficulty constant,
    /// not a per-file value: a deserialized chain resets it to
    /// [`DEFAULT_DIFFICULTY`], so a crafted chain file cannot declare its first
    /// retarget window mined at difficulty 1 and have that claim believed. A
    /// node that genuinely runs a lower-difficulty local network sets it through
    /// [`Blockchain::with_difficulty`] in memory, where it is trusted.
    #[serde(skip, default = "genesis_difficulty")]
    pub difficulty: usize,
    /// Pending transactions (mempool)
    #[serde(default)]
    pub pending_transactions: Vec<Transaction>,
    /// Mining reward
    pub mining_reward: u64,
    /// One balance per address: the account ledger, not a UTXO set.
    ///
    /// A derived index, never read from disk: it is rebuilt by replaying the
    /// chain, so it cannot disagree with the blocks.
    #[serde(skip)]
    balances: HashMap<String, u64>,
    /// Ids of every transaction already confirmed in the chain.
    ///
    /// Also derived. This is the replay guard: a signature is only good for the
    /// one transaction id it covers, and that id may only be confirmed once.
    #[serde(skip)]
    spent_tx_ids: HashSet<String>,
}

impl Blockchain {
    /// Create a new blockchain with genesis block
    ///
    /// # Example
    /// ```
    /// use rustchain::core::Blockchain;
    ///
    /// let blockchain = Blockchain::new();
    /// assert_eq!(blockchain.len(), 1); // Genesis block
    /// ```
    // SAFETY: `index_chain` is fallible in exactly three ways, a repeated
    // transaction id, a sender who cannot cover a spend, and a recipient
    // balance that overflows. `Block::genesis()` is a compile-time constant
    // carrying a single coinbase transaction, applied to an empty ledger, so
    // none of the three is reachable. `genesis_indexes_without_error` pins the
    // assumption, so a future change to the genesis block fails a test rather
    // than aborting a running node.
    #[allow(clippy::expect_used)]
    pub fn new() -> Self {
        let genesis = Block::genesis();
        let (balances, spent_tx_ids) = Self::index_chain(std::slice::from_ref(&genesis))
            .expect("the genesis block is always applicable");

        Self {
            chain: vec![genesis],
            difficulty: DEFAULT_DIFFICULTY,
            pending_transactions: Vec::new(),
            mining_reward: MINING_REWARD,
            balances,
            spent_tx_ids,
        }
    }

    /// Create a blockchain with custom difficulty
    pub fn with_difficulty(difficulty: usize) -> Self {
        let mut blockchain = Self::new();
        blockchain.difficulty = difficulty;
        blockchain
    }

    /// Get the latest block in the chain, or `None` if the chain is empty.
    ///
    /// Every constructor seeds the chain with a genesis block and
    /// [`Self::from_json`] refuses an empty one, so in practice this is always
    /// `Some`. It still returns an `Option` rather than asserting the
    /// invariant: `Blockchain`'s fields are public, and a node must not be
    /// killable by a value it was merely handed.
    pub fn latest_block(&self) -> Option<&Block> {
        self.chain.last()
    }

    /// Get the chain length
    pub fn len(&self) -> usize {
        self.chain.len()
    }

    /// Check if chain is empty (should never be true after initialization)
    pub fn is_empty(&self) -> bool {
        self.chain.is_empty()
    }

    /// Get balance of an address
    pub fn get_balance(&self, address: &str) -> u64 {
        *self.balances.get(address).unwrap_or(&0)
    }

    /// The difficulty the next block mined on this chain must carry.
    pub fn next_difficulty(&self) -> usize {
        Self::required_difficulty(&self.chain, self.difficulty)
    }

    /// The difficulty a block extending `chain` is required to claim.
    ///
    /// Difficulty is a property of the chain, not of node configuration: every
    /// node derives the same number from the same blocks, which is what makes a
    /// block's claimed difficulty checkable instead of merely reported.
    ///
    /// The rule is a moving-window retarget. Every [`RETARGET_INTERVAL`] blocks
    /// the wall-clock span of the window that just closed is compared with the
    /// span it should have taken, [`TARGET_BLOCK_TIME_SECS`] per block
    /// interval, and the difficulty moves one step if the two differ by more
    /// than a factor of [`RETARGET_TOLERANCE`]. In between retargets a block
    /// simply inherits its parent's difficulty.
    ///
    /// Difficulty counts leading hex zeros, so a single step is already a
    /// factor of 16 in work. That quantisation is the clamp: one retarget moves
    /// the difficulty by at most one step (a 16x change in required work) per
    /// window, and never outside [`MIN_DIFFICULTY`]..=[`MAX_DIFFICULTY`]. This
    /// is a coarser control than Bitcoin's 4x-per-retarget limit, not a
    /// stricter one, so it is a design simplification rather than a hardening.
    ///
    /// The genesis block is excluded from every window: its timestamp is a
    /// fixed constant chosen so all nodes agree on it, not a mining time.
    fn required_difficulty(chain: &[Block], base_difficulty: usize) -> usize {
        let clamp = |difficulty: usize| difficulty.clamp(MIN_DIFFICULTY, MAX_DIFFICULTY);

        let Some(parent) = chain.last() else {
            return clamp(base_difficulty);
        };

        // Height of the block being placed on top of `chain`.
        let height = chain.len() as u64;

        // The first mined block has no mined ancestor to inherit from.
        if height == 1 {
            return clamp(base_difficulty);
        }

        if !height.is_multiple_of(RETARGET_INTERVAL) {
            return clamp(parent.difficulty);
        }

        // The window is the block interval that just closed, with genesis
        // excluded, so the very first window is one interval shorter than the
        // rest. Measuring the expected span from the intervals actually
        // covered keeps the comparison honest either way.
        let window_start = (height - RETARGET_INTERVAL).max(1) as usize;
        let Some(first) = chain.get(window_start) else {
            return clamp(parent.difficulty);
        };

        let intervals = height.saturating_sub(window_start as u64 + 1) as i64;
        let expected = intervals.saturating_mul(TARGET_BLOCK_TIME_SECS);
        if expected <= 0 {
            return clamp(parent.difficulty);
        }

        // Timestamps are non-decreasing along a valid chain, but `chain` may be
        // untrusted input, so a negative span is floored rather than trusted.
        let actual = (parent.timestamp - first.timestamp).num_seconds().max(0);

        let retargeted = if actual.saturating_mul(RETARGET_TOLERANCE) < expected {
            // Blocks arrived too fast: make them harder.
            parent.difficulty.saturating_add(1)
        } else if actual > expected.saturating_mul(RETARGET_TOLERANCE) {
            // Blocks arrived too slowly: make them easier.
            parent.difficulty.saturating_sub(1)
        } else {
            parent.difficulty
        };

        clamp(retargeted)
    }

    /// Apply a block's transactions to a balance set and a spent-id set.
    ///
    /// This is the single definition of what a block does to the ledger, shared
    /// by block acceptance and by whole-chain validation, so the two can never
    /// disagree about whether a chain is affordable. A sender who cannot cover a
    /// transaction is an error, not a saturating subtraction: silently clamping
    /// to zero turns an impossible spend into invisible inflation.
    fn apply_block(
        block: &Block,
        balances: &mut HashMap<String, u64>,
        spent_tx_ids: &mut HashSet<String>,
    ) -> Result<(), BlockchainError> {
        for tx in &block.transactions {
            if !spent_tx_ids.insert(tx.id.clone()) {
                return Err(BlockchainError::InvalidTransaction(format!(
                    "Transaction {} appears more than once in the chain",
                    tx.id
                )));
            }

            if !tx.is_coinbase() {
                let sender_balance = balances.entry(tx.sender.clone()).or_insert(0);
                let remaining = sender_balance.checked_sub(tx.amount).ok_or(
                    BlockchainError::InsufficientBalance {
                        has: *sender_balance,
                        needs: tx.amount,
                    },
                )?;
                *sender_balance = remaining;
            }

            let recipient_balance = balances.entry(tx.recipient.clone()).or_insert(0);
            *recipient_balance = recipient_balance.checked_add(tx.amount).ok_or_else(|| {
                BlockchainError::InvalidTransaction(format!(
                    "Transaction {} overflows the recipient balance",
                    tx.id
                ))
            })?;
        }

        Ok(())
    }

    /// Replay a chain to derive the balances and the confirmed transaction ids.
    fn index_chain(
        chain: &[Block],
    ) -> Result<(HashMap<String, u64>, HashSet<String>), BlockchainError> {
        let mut balances = HashMap::new();
        let mut spent_tx_ids = HashSet::new();

        for block in chain {
            Self::apply_block(block, &mut balances, &mut spent_tx_ids)?;
        }

        Ok((balances, spent_tx_ids))
    }

    /// Checks that a block must satisfy relative to its predecessor.
    ///
    /// Shared by [`Self::validate_block`] and [`Self::is_valid`] so that a chain
    /// can never pass whole-chain validation with a block that block acceptance
    /// would have refused.
    fn check_block_structure(
        block: &Block,
        prefix: &[Block],
        expected_difficulty: usize,
        mining_reward: u64,
    ) -> Result<(), String> {
        let previous = prefix
            .last()
            .ok_or_else(|| "no previous block to build on".to_string())?;

        if block.index != previous.index + 1 {
            return Err(format!(
                "Invalid index: expected {}, got {}",
                previous.index + 1,
                block.index
            ));
        }

        if block.previous_hash != previous.hash {
            return Err("Previous hash mismatch".to_string());
        }

        // The block's own claim about how hard it was must be the number the
        // retarget rules produce at this height. Without this check the
        // difficulty is whatever the block says it is, and retargeting becomes
        // advisory: a miner would simply declare difficulty 1 forever.
        if block.difficulty != expected_difficulty {
            return Err(format!(
                "Invalid difficulty: expected {}, got {}",
                expected_difficulty, block.difficulty
            ));
        }

        // Recomputes the hash and checks the proof-of-work in one step. The
        // claimed difficulty is part of the preimage, so this also pins the
        // claim to the work that was actually done.
        if !block.verify_hash(Some(expected_difficulty)) {
            return Err("Block hash doesn't meet difficulty requirement".to_string());
        }

        if !block.verify_transactions() {
            return Err("Transaction verification failed".to_string());
        }

        // Verify coinbase: must have exactly one, and reward must not exceed allowed amount
        let coinbase_txs: Vec<_> = block
            .transactions
            .iter()
            .filter(|tx| tx.is_coinbase())
            .collect();
        if coinbase_txs.len() != 1 {
            return Err(format!(
                "Block must have exactly 1 coinbase transaction, has {}",
                coinbase_txs.len()
            ));
        }
        if coinbase_txs[0].amount > mining_reward {
            return Err("Coinbase reward exceeds allowed amount".to_string());
        }

        // Lower bound: median-time-past. A block's timestamp must be strictly
        // greater than the median of the previous up to `MEDIAN_TIME_SPAN`
        // blocks. Tying the floor to the median of real recent history, rather
        // than only to the immediate parent, stops one miner from setting a
        // timestamp low enough to steer the difficulty retarget, which reads
        // nothing but timestamps. It also degrades gracefully near genesis: a
        // window of one or two blocks reduces to "later than the parent".
        let mut window: Vec<i64> = prefix
            .iter()
            .rev()
            .take(MEDIAN_TIME_SPAN)
            .map(|b| b.timestamp.timestamp())
            .collect();
        window.sort_unstable();
        let median_time_past = window[window.len() / 2];
        if block.timestamp.timestamp() <= median_time_past {
            return Err(
                "Block timestamp is not past the median of the preceding blocks".to_string(),
            );
        }

        // Upper bound: a block may not run far ahead of our own clock.
        if block.timestamp.timestamp() > chrono::Utc::now().timestamp() + 7200 {
            // Allow 2 hours in the future
            return Err("Block timestamp too far in the future".to_string());
        }

        Ok(())
    }

    /// Add a transaction to the mempool
    ///
    /// # Arguments
    /// * `transaction` - The transaction to add
    ///
    /// # Returns
    /// Ok(()) if valid, Err if invalid
    pub fn add_transaction(&mut self, transaction: Transaction) -> Result<(), BlockchainError> {
        // Reject coinbase transactions from being added via mempool
        if transaction.is_coinbase() {
            return Err(BlockchainError::InvalidTransaction(
                "Cannot add coinbase transactions to mempool".to_string(),
            ));
        }

        // Validate transaction
        if !transaction.verify() {
            return Err(BlockchainError::InvalidTransaction(
                "Signature verification failed".to_string(),
            ));
        }

        // Replay guard: a signature is only ever good for one confirmation.
        if self.spent_tx_ids.contains(&transaction.id) {
            return Err(BlockchainError::InvalidTransaction(format!(
                "Transaction {} is already confirmed in the chain",
                transaction.id
            )));
        }
        if self
            .pending_transactions
            .iter()
            .any(|tx| tx.id == transaction.id)
        {
            return Err(BlockchainError::InvalidTransaction(format!(
                "Transaction {} is already in the mempool",
                transaction.id
            )));
        }

        // Check sender balance (skip for coinbase)
        if !transaction.is_coinbase() {
            let sender_balance = self.get_balance(&transaction.sender);
            if sender_balance < transaction.amount {
                return Err(BlockchainError::InsufficientBalance {
                    has: sender_balance,
                    needs: transaction.amount,
                });
            }
        }

        // Check for double-spend in mempool
        let pending_spent: u64 = self
            .pending_transactions
            .iter()
            .filter(|tx| tx.sender == transaction.sender)
            .map(|tx| tx.amount)
            .sum();

        let available = self
            .get_balance(&transaction.sender)
            .saturating_sub(pending_spent);
        if !transaction.is_coinbase() && available < transaction.amount {
            return Err(BlockchainError::InsufficientBalance {
                has: available,
                needs: transaction.amount,
            });
        }

        self.pending_transactions.push(transaction);
        Ok(())
    }

    /// Mine pending transactions into a new block
    ///
    /// # Arguments
    /// * `miner_address` - Address to receive mining reward
    ///
    /// # Returns
    /// The newly mined block, or the error that stopped it being added
    ///
    /// The mempool is only drained by a *successful* insert (inside
    /// [`Self::add_block`]). Emptying it up front lost every pending transaction
    /// whenever the block turned out to be unacceptable.
    pub fn mine_pending_transactions(
        &mut self,
        miner_address: &str,
    ) -> Result<Block, BlockchainError> {
        // Create coinbase transaction (mining reward)
        let coinbase = Transaction::coinbase(miner_address.to_string(), self.mining_reward);

        // Gather transactions for new block
        let mut transactions = vec![coinbase];
        transactions.extend(self.pending_transactions.iter().cloned());

        // Create and mine the block
        let latest = self.latest_block().ok_or(BlockchainError::EmptyChain)?;
        let previous_hash = latest.hash.clone();
        // The smallest timestamp the median-time-past rule will accept here is
        // one past the parent (the parent is the newest, hence largest, entry in
        // the median window of a normally built chain).
        let min_timestamp = latest.timestamp + chrono::Duration::seconds(1);
        let mut block = Block::new(self.chain.len() as u64, transactions, previous_hash);

        // A block mined right after its parent can land on the same wall-clock
        // tick, and an honest block this node produces must never be one its own
        // rules would reject. Nudging the timestamp past the parent keeps
        // median-time-past from failing on clock resolution alone.
        if block.timestamp < min_timestamp {
            block.timestamp = min_timestamp;
        }

        // Mine at the difficulty the chain rules demand at this height, not at
        // a node-local setting, anything else produces a block our own peers
        // would refuse.
        let difficulty = self.next_difficulty();

        log::info!(
            "Mining block {} with {} transactions (difficulty: {})...",
            block.index,
            block.transaction_count(),
            difficulty
        );

        let iterations = block.mine(difficulty);
        log::info!("Block mined in {} iterations", iterations);

        // Add block to chain
        self.add_block(block.clone())?;

        Ok(block)
    }

    /// Add a block to the chain (after validation)
    ///
    /// # Arguments
    /// * `block` - The block to add
    ///
    /// # Returns
    /// Ok(()) if valid and added, Err otherwise
    pub fn add_block(&mut self, block: Block) -> Result<(), BlockchainError> {
        // Validate the block, and take the ledger it produces
        let (balances, spent_tx_ids) = self.validate_block(&block)?;

        // Confirmed transactions leave the mempool
        let confirmed: HashSet<&String> = block.transactions.iter().map(|tx| &tx.id).collect();
        self.pending_transactions
            .retain(|tx| !confirmed.contains(&tx.id));

        self.balances = balances;
        self.spent_tx_ids = spent_tx_ids;
        self.chain.push(block);
        Ok(())
    }

    /// Validate a block before adding to chain
    ///
    /// # Returns
    /// The balances and spent-id index the chain would have *after* the block,
    /// so the caller commits exactly the state that was validated.
    fn validate_block(
        &self,
        block: &Block,
    ) -> Result<(HashMap<String, u64>, HashSet<String>), BlockchainError> {
        if self.chain.is_empty() {
            return Err(BlockchainError::EmptyChain);
        }

        Self::check_block_structure(
            block,
            &self.chain,
            self.next_difficulty(),
            self.mining_reward,
        )
        .map_err(BlockchainError::InvalidBlock)?;

        // Apply the block to a copy of the ledger. This is where a block that
        // spends coins nobody has, or repeats a transaction id, is refused,
        // signatures and proof-of-work alone say nothing about affordability.
        let mut balances = self.balances.clone();
        let mut spent_tx_ids = self.spent_tx_ids.clone();
        Self::apply_block(block, &mut balances, &mut spent_tx_ids)?;

        Ok((balances, spent_tx_ids))
    }

    /// Validate the entire blockchain
    ///
    /// Checks that:
    /// 1. The genesis block is *the* genesis block
    /// 2. Each block correctly references the previous
    /// 3. All hashes are valid and carry the proof-of-work the retarget rules
    ///    demand at their height
    /// 4. All transactions are valid, unique, and affordable
    ///
    /// This is what `rustchain validate` reports, so it has to enforce every
    /// rule block acceptance enforces, anything it skips is a rule an attacker
    /// can hand us a chain without.
    pub fn is_valid(&self) -> Result<(), BlockchainError> {
        // Validate genesis block: it is the root of all accounting, so it must
        // be the canonical one, not merely a well-shaped block.
        let genesis = self.chain.first().ok_or(BlockchainError::EmptyChain)?;
        if genesis.hash != Block::genesis().hash
            || !genesis.verify_hash(None)
            || !genesis.verify_transactions()
        {
            return Err(BlockchainError::InvalidChain(
                "Invalid genesis block".to_string(),
            ));
        }

        // Validate rest of chain. The required difficulty is re-derived from
        // the prefix each block was built on, so a chain cannot smuggle in an
        // easy block by claiming a difficulty its own history doesn't allow.
        for i in 1..self.chain.len() {
            Self::check_block_structure(
                &self.chain[i],
                &self.chain[..i],
                Self::required_difficulty(&self.chain[..i], self.difficulty),
                self.mining_reward,
            )
            .map_err(|e| BlockchainError::InvalidChain(format!("Block {}: {}", i, e)))?;
        }

        // Replay the whole chain: no transaction may be confirmed twice and no
        // sender may spend coins it never had.
        Self::index_chain(&self.chain)?;

        Ok(())
    }

    /// Get block by index
    pub fn get_block(&self, index: u64) -> Option<&Block> {
        self.chain.get(index as usize)
    }

    /// Get block by hash
    pub fn get_block_by_hash(&self, hash: &str) -> Option<&Block> {
        self.chain.iter().find(|b| b.hash == hash)
    }

    /// Get all transactions for an address
    pub fn get_transactions_for_address(&self, address: &str) -> Vec<&Transaction> {
        self.chain
            .iter()
            .flat_map(|block| &block.transactions)
            .filter(|tx| tx.sender == address || tx.recipient == address)
            .collect()
    }

    /// Get total coins in circulation
    ///
    /// Saturating for the same reason as [`Block::total_value`]: a chain that
    /// balanced to more than `u64::MAX` could never have been accepted, but a
    /// reporting call has no business being the thing that takes the node down
    /// if one ever were.
    pub fn total_supply(&self) -> u64 {
        self.balances
            .values()
            .copied()
            .fold(0u64, u64::saturating_add)
    }

    /// Get the total number of transactions in the chain
    pub fn total_transactions(&self) -> usize {
        self.chain.iter().map(|b| b.transaction_count()).sum()
    }

    /// Export chain to JSON
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// Import chain from JSON
    ///
    /// The file is untrusted input: the chain is validated, and the balances and
    /// spent-id index are recomputed from the blocks rather than read from the
    /// file, so an edited `balances` map cannot invent coins. Mempool entries
    /// from the file go back through the normal admission checks.
    pub fn from_json(json: &str) -> Result<Self, BlockchainError> {
        let mut blockchain: Self = serde_json::from_str(json)?;

        blockchain.is_valid()?;

        let (balances, spent_tx_ids) = Self::index_chain(&blockchain.chain)?;
        blockchain.balances = balances;
        blockchain.spent_tx_ids = spent_tx_ids;

        let pending = std::mem::take(&mut blockchain.pending_transactions);
        for tx in pending {
            let id = tx.id.clone();
            if let Err(e) = blockchain.add_transaction(tx) {
                log::warn!("Dropping stored pending transaction {}: {}", id, e);
            }
        }

        Ok(blockchain)
    }

    /// The total proof-of-work a chain represents: the summed work of its blocks.
    ///
    /// Fork choice is heaviest-work, not longest-chain. With a difficulty
    /// retarget the two orderings come apart: a long run of cheap blocks can be
    /// longer than a short run of hard ones while standing for far less work, so
    /// choosing on length alone lets a miner who drives the difficulty down win
    /// a reorg on block count (the time-warp attack). One leading hex zero is a
    /// factor of 16, so a block's work is `16^difficulty`, summed saturating so
    /// that an untrusted chain cannot overflow the accumulator.
    fn total_work(chain: &[Block]) -> u128 {
        chain
            .iter()
            .map(|block| 1u128 << block.difficulty.saturating_mul(4).min(127) as u32)
            .fold(0u128, u128::saturating_add)
    }

    /// Replace the chain with one that carries strictly more work (for consensus)
    pub fn replace_chain(&mut self, new_chain: Vec<Block>) -> Result<(), BlockchainError> {
        // Our own genesis, the root every candidate has to share. `chain` is a
        // public field, so a chainless `Blockchain` is a value a caller can
        // hand us; reading a tip that may not exist must be an error, not an
        // index panic.
        let our_genesis_hash = self
            .chain
            .first()
            .ok_or(BlockchainError::EmptyChain)?
            .hash
            .clone();

        let Some(their_genesis) = new_chain.first() else {
            return Err(BlockchainError::InvalidChain(
                "Incoming chain is empty".to_string(),
            ));
        };

        // The incoming chain must be rooted in *our* genesis block. Adopting a
        // foreign genesis moves this node onto an entirely different currency.
        if their_genesis.hash != our_genesis_hash {
            return Err(BlockchainError::InvalidChain(
                "Incoming chain has a different genesis block".to_string(),
            ));
        }

        // Validate the candidate in full before its work is allowed to mean
        // anything: seed a temporary chain from the shared genesis and re-add
        // every block through the same acceptance path, so a chain that dodges a
        // retarget, spends coins from nowhere or inflates a difficulty is
        // refused here rather than counted.
        let mut temp = Self::new();
        temp.chain = vec![their_genesis.clone()];
        temp.difficulty = self.difficulty;
        temp.mining_reward = self.mining_reward;
        let (balances, spent_tx_ids) = Self::index_chain(&temp.chain)?;
        temp.balances = balances;
        temp.spent_tx_ids = spent_tx_ids;

        for block in new_chain.iter().skip(1) {
            temp.add_block(block.clone())?;
        }

        // Only now, against a fully validated candidate whose per-block
        // difficulties are exactly the ones the retarget rules demand, is the
        // accumulated work meaningful. A tie or a lighter candidate loses: a
        // node never abandons work it holds for work it does not, even when the
        // lighter chain is the longer one.
        if Self::total_work(&temp.chain) <= Self::total_work(&self.chain) {
            return Err(BlockchainError::InvalidChain(
                "New chain does not carry more work than the current chain".to_string(),
            ));
        }

        // Transactions confirmed by us but not by the winning chain go back to
        // the mempool instead of vanishing
        let orphaned: Vec<Transaction> = self
            .chain
            .iter()
            .skip(1)
            .flat_map(|block| &block.transactions)
            .filter(|tx| !tx.is_coinbase() && !temp.spent_tx_ids.contains(&tx.id))
            .cloned()
            .collect();

        // Replace our chain
        self.chain = new_chain;
        self.balances = temp.balances;
        self.spent_tx_ids = temp.spent_tx_ids;

        // Re-admit the mempool against the new ledger
        let pending = std::mem::take(&mut self.pending_transactions);
        for tx in pending.into_iter().chain(orphaned) {
            let id = tx.id.clone();
            if let Err(e) = self.add_transaction(tx) {
                log::debug!("Dropping transaction {} after chain replacement: {}", id, e);
            }
        }

        Ok(())
    }
}

impl Default for Blockchain {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::transaction::SignError;
    use crate::wallet::Wallet;

    const TEST_DIFFICULTY: usize = 2;

    fn create_test_blockchain() -> Blockchain {
        Blockchain::with_difficulty(TEST_DIFFICULTY) // Low difficulty for fast tests
    }

    /// Hash of the chain tip, failing the test if the chain is empty.
    fn tip_hash(bc: &Blockchain) -> String {
        bc.latest_block().expect("the chain has a tip").hash.clone()
    }

    /// Mine a block, failing the test if it is not accepted.
    fn mine(bc: &mut Blockchain, miner_address: &str) -> Block {
        bc.mine_pending_transactions(miner_address)
            .expect("a freshly mined block must be acceptable")
    }

    /// Mine a block onto the tip *without* going through `add_block`, the way a
    /// deserialized or peer-supplied chain arrives.
    fn mined_block_on_tip(bc: &Blockchain, transactions: Vec<Transaction>) -> Block {
        let mut block = Block::new(bc.len() as u64, transactions, tip_hash(bc));
        block.mine(bc.next_difficulty());
        block
    }

    /// A chain of `blocks` blocks on top of genesis, spaced `spacing` seconds
    /// apart and all claiming `difficulty`.
    ///
    /// Only the fields the retarget reads, timestamp and difficulty, are
    /// meaningful; the blocks are never mined, which keeps the timing tests
    /// deterministic instead of dependent on how fast the machine hashes.
    fn timed_chain(blocks: u64, spacing: i64, difficulty: usize) -> Vec<Block> {
        let mut chain = vec![Block::genesis()];

        for index in 1..=blocks {
            let mut block = Block::new(index, Vec::new(), "prev".to_string());
            block.difficulty = difficulty;
            block.timestamp =
                chrono::DateTime::UNIX_EPOCH + chrono::Duration::seconds(index as i64 * spacing);
            chain.push(block);
        }

        chain
    }

    /// The difficulty demanded of the block that closes the first retarget
    /// window, given blocks arriving `spacing` seconds apart.
    fn difficulty_after_first_window(spacing: i64, difficulty: usize) -> usize {
        let chain = timed_chain(RETARGET_INTERVAL - 1, spacing, difficulty);
        assert_eq!(chain.len() as u64, RETARGET_INTERVAL);
        Blockchain::required_difficulty(&chain, difficulty)
    }

    /// A blockchain of `blocks` *real* mined blocks on top of genesis, each
    /// timestamped `spacing` seconds after the last, mined at whatever
    /// difficulty the retarget rules demand at its height.
    ///
    /// Unlike [`timed_chain`], every block here carries genuine proof-of-work
    /// and passes block acceptance, so the result is a chain the acceptance path
    /// itself produced. Controlling the spacing lets a test pin how the first
    /// retarget lands, and hence how much work the chain represents.
    fn timed_mined_bc(base_difficulty: usize, blocks: u64, spacing: i64) -> Blockchain {
        let mut bc = Blockchain::with_difficulty(base_difficulty);
        for i in 1..=blocks {
            let coinbase = Transaction::coinbase("miner".to_string(), bc.mining_reward);
            let previous_hash = tip_hash(&bc);
            let mut block = Block::new(bc.len() as u64, vec![coinbase], previous_hash);
            block.timestamp =
                chrono::DateTime::UNIX_EPOCH + chrono::Duration::seconds(i as i64 * spacing);
            block.mine(bc.next_difficulty());
            bc.add_block(block)
                .expect("a paced block at the demanded difficulty is acceptable");
        }
        bc
    }

    #[test]
    fn test_new_blockchain() {
        let bc = create_test_blockchain();

        assert_eq!(bc.len(), 1);
        assert!(bc.is_valid().is_ok());
    }

    #[test]
    fn test_genesis_balance() {
        let bc = create_test_blockchain();

        assert_eq!(bc.get_balance("genesis_address"), 1_000_000);
    }

    #[test]
    fn test_add_transaction() {
        let mut bc = create_test_blockchain();

        let mut tx = Transaction::new("genesis_address".to_string(), "bob".to_string(), 100);
        // A malformed key is rejected as an error, not a panic.
        assert_eq!(
            tx.sign("genesis_private_key"),
            Err(SignError::InvalidHex("Odd number of digits".to_string()))
        );
        assert!(
            tx.signature.is_none(),
            "a failed signing must not mutate the transaction"
        );

        // An unsigned transaction is refused by the chain.
        assert!(bc.add_transaction(tx).is_err());
    }

    #[test]
    fn test_insufficient_balance() {
        let mut bc = create_test_blockchain();

        let mut tx = Transaction::new("empty_address".to_string(), "bob".to_string(), 100);
        // With real crypto, this would need a valid ed25519 key
        tx.signature = Some("dummy".to_string());

        let result = bc.add_transaction(tx);
        assert!(result.is_err());
    }

    #[test]
    fn test_mine_block() {
        let mut bc = create_test_blockchain();

        let block = mine(&mut bc, "miner");

        assert_eq!(bc.len(), 2);
        assert!(block.hash.starts_with("00"));
        assert!(bc.is_valid().is_ok());
    }

    #[test]
    fn test_balance_after_mining() {
        let mut bc = create_test_blockchain();

        mine(&mut bc, "miner");

        assert_eq!(bc.get_balance("miner"), MINING_REWARD);
    }

    #[test]
    fn test_chain_validation() {
        let mut bc = create_test_blockchain();

        mine(&mut bc, "miner");
        mine(&mut bc, "miner");

        assert!(bc.is_valid().is_ok());
    }

    #[test]
    fn test_tamper_detection() {
        let mut bc = create_test_blockchain();
        mine(&mut bc, "miner");

        // Tamper with a block
        bc.chain[1].transactions[0].amount = 999999;

        assert!(bc.is_valid().is_err());
    }

    #[test]
    fn test_json_serialization() {
        let bc = create_test_blockchain();

        let json = bc.to_json().unwrap();
        let restored = Blockchain::from_json(&json).unwrap();

        assert_eq!(bc.len(), restored.len());
        assert_eq!(tip_hash(&bc), tip_hash(&restored));
    }

    #[test]
    fn test_coinbase_rejected_from_mempool() {
        let mut bc = create_test_blockchain();
        let coinbase = Transaction::coinbase("attacker".to_string(), 1_000_000);
        let result = bc.add_transaction(coinbase);
        assert!(result.is_err());
    }

    #[test]
    fn block_repeating_a_payment_is_rejected() {
        // Regression (CVE-2012-2459): the Merkle tree padded odd levels by
        // duplicating the last leaf, so [coinbase, filler, pay] and
        // [coinbase, filler, pay, pay] had the same root and therefore the same
        // block hash, a way to mint coins by repeating a payment.
        let mut bc = create_test_blockchain();
        let alice = Wallet::new();
        mine(&mut bc, &alice.address);

        let filler = alice
            .create_transaction("filler", 1)
            .expect("a generated wallet key must sign");
        let payment = alice
            .create_transaction("bob", 40)
            .expect("a generated wallet key must sign");
        let coinbase = Transaction::coinbase("miner".to_string(), bc.mining_reward);

        let honest =
            mined_block_on_tip(&bc, vec![coinbase.clone(), filler.clone(), payment.clone()]);
        let doubled = mined_block_on_tip(&bc, vec![coinbase, filler, payment.clone(), payment]);

        assert_ne!(
            honest.merkle_root, doubled.merkle_root,
            "duplicating the last transaction must change the Merkle root"
        );
        assert!(
            bc.add_block(doubled).is_err(),
            "a block repeating a transaction must be rejected"
        );
    }

    #[test]
    fn block_spending_coins_that_do_not_exist_is_rejected() {
        // Regression: validate_block checked signatures and proof-of-work but
        // never affordability, and add_block debited with saturating_sub, so a
        // block could credit a recipient with coins nobody ever had.
        let mut bc = create_test_blockchain();
        let pauper = Wallet::new();

        let tx = pauper
            .create_transaction("recipient", 1_000_000)
            .expect("a generated wallet key must sign");
        assert!(
            bc.add_transaction(tx.clone()).is_err(),
            "the mempool refuses it"
        );

        let coinbase = Transaction::coinbase("miner".to_string(), bc.mining_reward);
        let block = mined_block_on_tip(&bc, vec![coinbase, tx]);

        assert!(matches!(
            bc.add_block(block),
            Err(BlockchainError::InsufficientBalance { .. })
        ));
        assert_eq!(bc.get_balance("recipient"), 0);
        assert_eq!(bc.len(), 1);
    }

    #[test]
    fn is_valid_rejects_a_chain_without_proof_of_work() {
        // Regression: is_valid never compared block hashes against the
        // difficulty, so a chain forged in microseconds was reported "Valid!".
        let mut bc = create_test_blockchain();

        let coinbase = Transaction::coinbase("attacker".to_string(), bc.mining_reward);
        let unmined = Block::new(1, vec![coinbase], tip_hash(&bc));
        assert!(
            !unmined.hash.starts_with("00"),
            "this fixture is only meaningful for an unmined block"
        );

        bc.chain.push(unmined);

        assert!(bc.is_valid().is_err());
    }

    #[test]
    fn is_valid_rejects_a_chain_that_spends_coins_from_nowhere() {
        let mut bc = create_test_blockchain();
        let pauper = Wallet::new();

        let tx = pauper
            .create_transaction("recipient", 1_000_000)
            .expect("a generated wallet key must sign");
        let coinbase = Transaction::coinbase("miner".to_string(), bc.mining_reward);
        let block = mined_block_on_tip(&bc, vec![coinbase, tx]);
        bc.chain.push(block);

        assert!(bc.is_valid().is_err());
    }

    #[test]
    fn promoting_a_payment_to_a_coinbase_is_detected() {
        // Regression: hash() omitted is_coinbase_tx and public_key, so a payment
        // could be turned into a coinbase, which skips signature checks, with
        // no change to the Merkle root or the block hash.
        let mut bc = create_test_blockchain();
        let alice = Wallet::new();
        mine(&mut bc, &alice.address);

        let tx = alice
            .create_transaction("bob", 10)
            .expect("a generated wallet key must sign");
        bc.add_transaction(tx).expect("alice can afford 10 coins");
        mine(&mut bc, &alice.address);

        bc.chain[2].transactions[1].is_coinbase_tx = true;
        bc.chain[2].transactions[1].public_key = None;

        assert!(bc.is_valid().is_err());
    }

    #[test]
    fn a_signature_cannot_be_replayed() {
        // Regression: the same signed transaction could be mined over and over,
        // draining the sender from a single captured signature.
        let mut bc = create_test_blockchain();
        let alice = Wallet::new();
        mine(&mut bc, &alice.address);

        let tx = alice
            .create_transaction("bob", 10)
            .expect("a generated wallet key must sign");

        bc.add_transaction(tx.clone())
            .expect("the first submission is valid");
        mine(&mut bc, "miner");
        assert_eq!(bc.get_balance("bob"), 10);

        assert!(
            bc.add_transaction(tx.clone()).is_err(),
            "the mempool refuses a replay"
        );

        let coinbase = Transaction::coinbase("miner".to_string(), bc.mining_reward);
        let replay_block = mined_block_on_tip(&bc, vec![coinbase, tx]);
        assert!(
            bc.add_block(replay_block).is_err(),
            "a block replaying it is refused"
        );
        assert_eq!(bc.get_balance("bob"), 10);
    }

    #[test]
    fn mempool_survives_persistence() {
        // Regression: pending_transactions was #[serde(skip)], so the documented
        // `transaction create` -> `mine` workflow silently discarded every
        // transaction while printing success.
        //
        // Built at the network's genesis difficulty rather than the test one:
        // the base difficulty is no longer read from the file, so a chain that
        // mined blocks only reloads when it was mined at DEFAULT_DIFFICULTY. One
        // block at that difficulty is still cheap.
        let mut bc = Blockchain::new();
        let alice = Wallet::new();
        mine(&mut bc, &alice.address);

        let tx = alice
            .create_transaction("bob", 10)
            .expect("a generated wallet key must sign");
        bc.add_transaction(tx.clone())
            .expect("alice can afford 10 coins");

        let restored = Blockchain::from_json(&bc.to_json().unwrap()).unwrap();

        assert_eq!(restored.pending_transactions.len(), 1);
        assert_eq!(restored.pending_transactions[0].id, tx.id);
    }

    #[test]
    fn a_default_difficulty_chain_round_trips_through_the_file() {
        // A chain mined at the network's genesis difficulty survives a round
        // trip through the on-disk format: hashes, balances and supply all come
        // back. This is the generated-chain persistence coverage the fast
        // property test can no longer give, now that the base difficulty is not
        // read from the file.
        let mut bc = Blockchain::new();
        let alice = Wallet::new();
        mine(&mut bc, &alice.address);
        let tx = alice
            .create_transaction("bob", 10)
            .expect("a generated wallet key must sign");
        bc.add_transaction(tx).expect("alice can afford 10 coins");
        mine(&mut bc, "miner");

        let reloaded = Blockchain::from_json(&bc.to_json().unwrap()).unwrap();

        assert_eq!(reloaded.len(), bc.len());
        assert_eq!(tip_hash(&reloaded), tip_hash(&bc));
        assert_eq!(reloaded.get_balance("bob"), 10);
        assert_eq!(reloaded.total_supply(), bc.total_supply());
        assert!(reloaded.is_valid().is_ok());
    }

    #[test]
    fn from_json_recomputes_balances_from_the_chain() {
        // Regression: balances were deserialized straight from the file, so
        // editing the file made `rustchain balance` report anything at all.
        let bc = create_test_blockchain();
        let mut value: serde_json::Value = serde_json::from_str(&bc.to_json().unwrap()).unwrap();
        value["balances"] = serde_json::json!({ "attacker": 999_999_999u64 });

        let restored = Blockchain::from_json(&value.to_string()).unwrap();

        assert_eq!(restored.get_balance("attacker"), 0);
        assert_eq!(restored.get_balance("genesis_address"), 1_000_000);
    }

    #[test]
    fn from_json_rejects_an_invalid_chain() {
        let mut bc = create_test_blockchain();
        mine(&mut bc, "miner");
        let json = bc.to_json().unwrap();

        let mut value: serde_json::Value = serde_json::from_str(&json).unwrap();
        value["chain"][1]["transactions"][0]["amount"] = serde_json::json!(999_999u64);

        assert!(Blockchain::from_json(&value.to_string()).is_err());
    }

    #[test]
    fn replace_chain_rejects_a_foreign_genesis() {
        // Regression: whatever genesis a peer sent became the trusted root, and
        // the replacement balances were derived from a genesis that was then
        // thrown away.
        let mut bc = create_test_blockchain();
        let our_genesis = bc.chain[0].hash.clone();

        let mut foreign_genesis = Block::genesis();
        foreign_genesis.transactions[0].recipient = "attacker".to_string();
        foreign_genesis.hash = foreign_genesis.calculate_hash();
        let filler = Block::new(1, vec![], foreign_genesis.hash.clone());
        let foreign_chain = vec![
            foreign_genesis,
            filler.clone(),
            Block::new(2, vec![], filler.hash.clone()),
        ];

        assert!(bc.replace_chain(foreign_chain).is_err());
        assert_eq!(bc.chain[0].hash, our_genesis);
        assert_eq!(bc.get_balance("attacker"), 0);
    }

    #[test]
    fn a_failed_mine_keeps_the_mempool() {
        // Regression: the mempool was drained before the block was validated and
        // add_block failure was swallowed, so a rejected block destroyed every
        // pending transaction while the CLI printed "Block mined!".
        let mut bc = create_test_blockchain();
        let pauper = Wallet::new();

        // An unaffordable transaction, placed directly in the mempool the way a
        // reorg or a stale mempool entry would leave one.
        let tx = pauper
            .create_transaction("recipient", 1_000_000)
            .expect("a generated wallet key must sign");
        bc.pending_transactions.push(tx);

        assert!(bc.mine_pending_transactions("miner").is_err());
        assert_eq!(bc.pending_transactions.len(), 1, "the mempool must survive");
        assert_eq!(bc.len(), 1);
    }

    #[test]
    fn genesis_indexes_without_error() {
        // Pins the assumption behind the one `expect` left in `Blockchain::new`:
        // a lone genesis block cannot fail to index. If the genesis block ever
        // grows a second transaction or a non-coinbase spend, this fails here
        // instead of aborting a node at startup.
        let genesis = Block::genesis();
        assert!(Blockchain::index_chain(std::slice::from_ref(&genesis)).is_ok());
    }

    #[test]
    fn an_empty_chain_errors_instead_of_panicking() {
        // `chain` is a public field, so a caller can hand us a chainless
        // blockchain. Every path that needs a tip must report it, not abort.
        let mut bc = create_test_blockchain();
        bc.chain.clear();

        assert!(bc.latest_block().is_none());
        assert!(matches!(bc.is_valid(), Err(BlockchainError::EmptyChain)));
        assert!(matches!(
            bc.mine_pending_transactions("miner"),
            Err(BlockchainError::EmptyChain)
        ));
        assert!(matches!(
            bc.add_block(Block::genesis()),
            Err(BlockchainError::EmptyChain)
        ));
    }

    #[test]
    fn difficulty_is_inherited_between_retargets() {
        // Only a block at a retarget boundary may change the difficulty, no
        // matter how fast the blocks in between arrive.
        let chain = timed_chain(RETARGET_INTERVAL - 2, 1, 7);

        assert!(!(chain.len() as u64).is_multiple_of(RETARGET_INTERVAL));
        assert_eq!(Blockchain::required_difficulty(&chain, TEST_DIFFICULTY), 7);
    }

    #[test]
    fn difficulty_rises_when_blocks_come_too_fast() {
        // A tenth of the target block time per block: far too fast.
        let spacing = TARGET_BLOCK_TIME_SECS / 10;

        assert_eq!(
            difficulty_after_first_window(spacing, TEST_DIFFICULTY),
            TEST_DIFFICULTY + 1
        );
    }

    #[test]
    fn difficulty_falls_when_blocks_come_too_slow() {
        // Ten times the target block time per block: far too slow.
        let spacing = TARGET_BLOCK_TIME_SECS * 10;

        assert_eq!(
            difficulty_after_first_window(spacing, TEST_DIFFICULTY),
            TEST_DIFFICULTY - 1
        );
    }

    #[test]
    fn difficulty_holds_when_blocks_arrive_on_target() {
        // The steady state, measured on a full window rather than the shorter
        // first one: on-target blocks must not make the difficulty drift.
        let chain = timed_chain(
            RETARGET_INTERVAL * 2 - 1,
            TARGET_BLOCK_TIME_SECS,
            TEST_DIFFICULTY,
        );

        assert_eq!(chain.len() as u64, RETARGET_INTERVAL * 2);
        assert_eq!(
            Blockchain::required_difficulty(&chain, TEST_DIFFICULTY),
            TEST_DIFFICULTY
        );
    }

    #[test]
    fn a_retarget_moves_the_difficulty_by_at_most_one_step() {
        // Every block sharing a timestamp is the most extreme "too fast" a
        // chain can express. One leading zero is already a factor of 16 in
        // work, so the response is capped at a single step in either
        // direction.
        assert_eq!(
            difficulty_after_first_window(0, TEST_DIFFICULTY),
            TEST_DIFFICULTY + 1
        );
        assert_eq!(
            difficulty_after_first_window(TARGET_BLOCK_TIME_SECS * 1_000, TEST_DIFFICULTY),
            TEST_DIFFICULTY - 1
        );
    }

    #[test]
    fn difficulty_never_falls_below_the_floor() {
        // At difficulty 0 a block needs no work at all, so however slow the
        // chain gets, the retarget stops at the floor.
        let spacing = TARGET_BLOCK_TIME_SECS * 1_000;

        assert_eq!(
            difficulty_after_first_window(spacing, MIN_DIFFICULTY),
            MIN_DIFFICULTY
        );
    }

    #[test]
    fn mining_retargets_at_the_interval_boundary() {
        // Blocks mined back to back arrive far faster than the target, so the
        // block that closes the first window has to be harder than the ones
        // before it, and the chain that demanded that must then accept it.
        let mut bc = Blockchain::with_difficulty(MIN_DIFFICULTY);

        for _ in 1..RETARGET_INTERVAL {
            mine(&mut bc, "miner");
        }
        assert!(
            bc.chain[1..].iter().all(|b| b.difficulty == MIN_DIFFICULTY),
            "no retarget before the interval closes"
        );

        let retargeted = mine(&mut bc, "miner");

        assert_eq!(retargeted.index, RETARGET_INTERVAL);
        assert_eq!(retargeted.difficulty, MIN_DIFFICULTY + 1);
        assert!(bc.is_valid().is_ok());
    }

    #[test]
    fn a_block_claiming_the_wrong_difficulty_is_rejected() {
        let mut bc = create_test_blockchain();
        assert_eq!(bc.next_difficulty(), TEST_DIFFICULTY);

        fn mined_at(bc: &Blockchain, difficulty: usize) -> Block {
            let coinbase = Transaction::coinbase("miner".to_string(), bc.mining_reward);
            let mut block = Block::new(1, vec![coinbase], tip_hash(bc));
            block.mine(difficulty);
            block
        }

        let cheap = mined_at(&bc, TEST_DIFFICULTY - 1);
        assert!(
            bc.add_block(cheap).is_err(),
            "a block claiming less work than the rules demand is refused"
        );

        let overclaimed = mined_at(&bc, TEST_DIFFICULTY + 1);
        assert!(
            bc.add_block(overclaimed).is_err(),
            "so is one claiming a difficulty the rules never set"
        );

        assert_eq!(bc.len(), 1);
    }

    #[test]
    fn is_valid_rejects_a_chain_that_dodges_a_retarget() {
        // Regression cover for the whole point of validating the claim: an
        // attacker re-mines the retargeted block at the old, cheap difficulty.
        // The proof-of-work is internally consistent, so only re-deriving the
        // required difficulty from the chain catches it.
        let mut bc = Blockchain::with_difficulty(MIN_DIFFICULTY);
        for _ in 1..=RETARGET_INTERVAL {
            mine(&mut bc, "miner");
        }

        let boundary = RETARGET_INTERVAL as usize;
        assert_eq!(bc.chain[boundary].difficulty, MIN_DIFFICULTY + 1);

        bc.chain[boundary].mine(MIN_DIFFICULTY);
        assert!(bc.chain[boundary].verify_hash(Some(MIN_DIFFICULTY)));

        assert!(bc.is_valid().is_err());
    }

    #[test]
    fn a_longer_but_lighter_chain_is_rejected() {
        // The time-warp reorg the heaviest-work rule closes. The honest chain
        // mines a full retarget window back to back, so its closing block is
        // harder and the chain represents more work over fewer blocks. The
        // attacker paces timestamps on target so the difficulty never leaves the
        // floor, then keeps extending: a strictly longer chain that, block for
        // block, cost far less work.
        let mut honest = Blockchain::with_difficulty(MIN_DIFFICULTY);
        for _ in 0..RETARGET_INTERVAL {
            mine(&mut honest, "honest-miner");
        }
        assert_eq!(
            honest.chain[RETARGET_INTERVAL as usize].difficulty,
            MIN_DIFFICULTY + 1
        );

        // On-target spacing keeps the retarget from raising the difficulty, so
        // every attacker block stays at the floor.
        let attacker = timed_mined_bc(
            MIN_DIFFICULTY,
            RETARGET_INTERVAL + 3,
            TARGET_BLOCK_TIME_SECS,
        );
        assert!(
            attacker.chain[1..]
                .iter()
                .all(|b| b.difficulty == MIN_DIFFICULTY),
            "the attack chain never leaves the difficulty floor"
        );

        // The attack chain is strictly longer, internally valid, and yet
        // lighter: exactly the shape length-based fork choice would have adopted.
        assert!(attacker.len() > honest.len());
        assert!(attacker.is_valid().is_ok());
        assert!(Blockchain::total_work(&attacker.chain) < Blockchain::total_work(&honest.chain));

        assert!(
            matches!(
                honest.replace_chain(attacker.chain.clone()),
                Err(BlockchainError::InvalidChain(_))
            ),
            "a longer chain carrying less work must be refused"
        );
        assert_eq!(honest.len(), RETARGET_INTERVAL as usize + 1);
    }

    #[test]
    fn a_block_with_a_stale_timestamp_is_rejected() {
        // Median-time-past: a block must be later than the median of the recent
        // window, so a miner cannot backdate a block to steer the retarget,
        // which reads nothing but timestamps.
        let mut bc = timed_mined_bc(TEST_DIFFICULTY, 5, 10_000);
        // The window is [genesis(0), 10000, 20000, 30000, 40000, 50000]; its
        // median is 30000, and the tip is at 50000.

        let mined_at = |bc: &Blockchain, seconds: i64| {
            let coinbase = Transaction::coinbase("miner".to_string(), bc.mining_reward);
            let mut block = Block::new(bc.len() as u64, vec![coinbase], tip_hash(bc));
            block.timestamp = chrono::DateTime::UNIX_EPOCH + chrono::Duration::seconds(seconds);
            block.mine(bc.next_difficulty());
            block
        };

        // A timestamp past the window is accepted.
        assert!(bc.clone().add_block(mined_at(&bc, 60_000)).is_ok());

        // A well-formed, correctly-mined block whose only fault is a timestamp at
        // or below the median is refused.
        assert!(matches!(
            bc.add_block(mined_at(&bc, 25_000)),
            Err(BlockchainError::InvalidBlock(_))
        ));
    }

    #[test]
    fn from_json_anchors_the_base_difficulty_to_the_network_constant() {
        // The starting difficulty is trusted in memory but not from a file. A
        // chain mined on a low-difficulty local network is valid where its base
        // is configured, yet fails to load, because a loaded chain is validated
        // against DEFAULT_DIFFICULTY rather than whatever base the file implied.
        // Without this, a crafted file could declare its first retarget window
        // mined at difficulty 1.
        let mut bc = Blockchain::with_difficulty(MIN_DIFFICULTY);
        mine(&mut bc, "miner");
        assert_eq!(bc.chain[1].difficulty, MIN_DIFFICULTY);
        assert!(bc.is_valid().is_ok());

        let json = bc.to_json().unwrap();
        assert!(
            Blockchain::from_json(&json).is_err(),
            "a below-default base difficulty must not survive a round trip through the file"
        );
    }

    #[test]
    fn replace_chain_on_an_empty_chain_errors_instead_of_panicking() {
        // `chain` is public, so a caller can hand us a chainless blockchain.
        // Reading the genesis to compare against must report the empty chain,
        // not index-panic.
        let mut bc = create_test_blockchain();
        let candidate = bc.chain.clone();
        bc.chain.clear();

        assert!(matches!(
            bc.replace_chain(candidate),
            Err(BlockchainError::EmptyChain)
        ));
    }
}
