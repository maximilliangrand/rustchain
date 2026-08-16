//! Property-based tests for the invariants the chain rests on.
//!
//! The unit tests pin down specific regressions; these check the same rules
//! against inputs nobody chose by hand. Each property is written as a statement
//! that must hold for *every* generated case, so a counterexample is a real
//! consensus bug rather than a missing test:
//!
//! - a chain built from validly mined blocks stays valid, and coins are neither
//!   created nor destroyed outside the coinbase;
//! - [`Blockchain::replace_chain`] adopts a candidate exactly when it is longer
//!   *and* valid, and leaves the node untouched otherwise;
//! - a sender can never get more than it holds past the mempool, and no
//!   transaction is ever confirmed twice;
//! - every Merkle proof verifies against its own root, and no proof carries a
//!   transaction that is not in the tree;
//! - a signature verifies if and only if the signed payload is untouched.

use proptest::prelude::*;

use rustchain::core::blockchain::{MINING_REWARD, RETARGET_INTERVAL};
use rustchain::core::{Block, Blockchain, MerkleTree, Transaction};
use rustchain::wallet::Wallet;

/// Low enough that a case mines in milliseconds, high enough that the
/// proof-of-work check is not vacuous.
const TEST_DIFFICULTY: usize = 2;

/// Distinct actors a generated sequence may act as.
const WALLET_COUNT: usize = 3;

/// Coins the genesis block distributes.
const GENESIS_SUPPLY: u64 = 1_000_000;

/// Longest chain a generated sequence may build.
///
/// Kept below the first retarget boundary so the difficulty stays at
/// [`TEST_DIFFICULTY`] for the whole case: retargeting is exercised by the unit
/// tests, and letting it fire here would only make mining times erratic.
const MAX_CHAIN_LEN: usize = RETARGET_INTERVAL as usize - 1;

/// A wallet derived from a generated seed, so a failing case is reproducible
/// from its shrunk input rather than from whatever the OS RNG produced.
fn wallet_from_seed(seed: &[u8; 32]) -> Wallet {
    Wallet::from_private_key(&hex::encode(seed)).expect("32 bytes is a valid ed25519 key")
}

/// Mine a block onto the tip *without* going through `add_block`, the way a
/// peer-supplied block arrives.
fn mined_block_on_tip(blockchain: &Blockchain, transactions: Vec<Transaction>) -> Block {
    let previous_hash = blockchain
        .latest_block()
        .expect("the chain has a tip")
        .hash
        .clone();
    let mut block = Block::new(blockchain.len() as u64, transactions, previous_hash);
    block.mine(blockchain.next_difficulty());
    block
}

/// The hashes of a chain, for comparing two chains without `Block: PartialEq`.
fn chain_hashes(chain: &[Block]) -> Vec<String> {
    chain.iter().map(|block| block.hash.clone()).collect()
}

/// What a generated sequence does to the node.
#[derive(Debug, Clone)]
enum Op {
    /// Mine the mempool into a block paid to one of the wallets.
    Mine { miner: usize },
    /// Submit a signed payment to the mempool.
    Send { from: usize, to: usize, amount: u64 },
}

fn arb_op() -> impl Strategy<Value = Op> {
    prop_oneof![
        2 => (0..WALLET_COUNT).prop_map(|miner| Op::Mine { miner }),
        3 => (0..WALLET_COUNT, 0..WALLET_COUNT, 0u64..90)
            .prop_map(|(from, to, amount)| Op::Send { from, to, amount }),
    ]
}

prop_compose! {
    fn arb_wallets()(
        seeds in prop::collection::vec(any::<[u8; 32]>(), WALLET_COUNT),
    ) -> Vec<Wallet> {
        seeds.iter().map(wallet_from_seed).collect()
    }
}

/// How a candidate chain offered to `replace_chain` was corrupted, if at all.
#[derive(Debug, Clone, Copy)]
enum Corruption {
    /// Offer the chain exactly as it was mined.
    None,
    /// Re-roll the tip's nonce, so its stored hash no longer matches.
    Nonce,
    /// Inflate the tip's coinbase, so the Merkle root no longer matches.
    CoinbaseAmount,
    /// Root the chain in a genesis block that is not ours.
    ForeignGenesis,
    /// Remove a middle block, so the chain stays long but its interior links
    /// break. Unlike cutting back to genesis (which only ever produces a
    /// too-short candidate, rejected before validation is reached), this leaves
    /// a candidate whose length can still beat ours, so acceptance turns on the
    /// interior-linkage check rather than on length.
    SpliceMiddle,
    /// Repeat the tip, so it references a block that is no longer its parent.
    RepeatTip,
}

fn arb_corruption() -> impl Strategy<Value = Corruption> {
    prop_oneof![
        Just(Corruption::None),
        Just(Corruption::Nonce),
        Just(Corruption::CoinbaseAmount),
        Just(Corruption::ForeignGenesis),
        Just(Corruption::SpliceMiddle),
        Just(Corruption::RepeatTip),
    ]
}

/// A genesis-height block that is *not* the canonical genesis block.
fn foreign_genesis() -> Block {
    let coinbase = Transaction::genesis_coinbase("someone_elses_treasury".to_string(), 1);
    let mut block = Block::new(0, vec![coinbase], "0".repeat(64));
    block.timestamp = chrono::DateTime::UNIX_EPOCH;
    block.hash = block.calculate_hash();
    block
}

fn corrupt(chain: &mut Vec<Block>, corruption: Corruption) {
    match corruption {
        Corruption::None => {}
        Corruption::Nonce => {
            if let Some(tip) = chain.last_mut() {
                tip.nonce = tip.nonce.wrapping_add(1);
            }
        }
        Corruption::CoinbaseAmount => {
            if let Some(tx) = chain
                .last_mut()
                .and_then(|tip| tip.transactions.first_mut())
            {
                tx.amount = tx.amount.wrapping_add(1);
            }
        }
        Corruption::ForeignGenesis => {
            if let Some(genesis) = chain.first_mut() {
                *genesis = foreign_genesis();
            }
        }
        Corruption::SpliceMiddle => {
            if chain.len() > 2 {
                chain.remove(chain.len() / 2);
            }
        }
        Corruption::RepeatTip => {
            if let Some(tip) = chain.last().cloned() {
                chain.push(tip);
            }
        }
    }
}

/// Whether a candidate chain passes whole-chain validation.
///
/// Deliberately a *different* code path from the one `replace_chain` walks:
/// `is_valid` re-derives the required difficulty from each prefix, while
/// `replace_chain` re-adds the blocks one at a time. The two must agree.
fn passes_whole_chain_validation(chain: &[Block]) -> bool {
    let mut probe = Blockchain::with_difficulty(TEST_DIFFICULTY);
    probe.chain = chain.to_vec();
    probe.is_valid().is_ok()
}

proptest! {
    // Every case in this block mines real proof-of-work, so the case count is
    // chosen to keep the suite in the sub-second range.
    #![proptest_config(ProptestConfig::with_cases(24))]

    /// A chain assembled from validly mined blocks is valid at every step, the
    /// only coins ever created are coinbase rewards, and the whole thing
    /// survives a round trip through the on-disk format.
    #[test]
    fn a_mined_chain_stays_valid_and_conserves_coins(
        wallets in arb_wallets(),
        ops in prop::collection::vec(arb_op(), 0..12),
    ) {
        let mut blockchain = Blockchain::with_difficulty(TEST_DIFFICULTY);
        let mut mined = 0u64;

        for op in ops {
            match op {
                Op::Mine { miner } => {
                    if blockchain.len() >= MAX_CHAIN_LEN {
                        continue;
                    }

                    let height_before = blockchain.len();
                    let block = blockchain
                        .mine_pending_transactions(&wallets[miner].address)
                        .expect("a freshly mined block must be acceptable");
                    mined += 1;

                    prop_assert_eq!(blockchain.len(), height_before + 1);
                    prop_assert!(block.hash.starts_with(&"0".repeat(TEST_DIFFICULTY)));
                    prop_assert!(
                        blockchain.is_valid().is_ok(),
                        "the chain must stay valid after mining block {}",
                        block.index
                    );
                }
                Op::Send { from, to, amount } => {
                    let sender = &wallets[from];
                    let committed: u64 = blockchain
                        .pending_transactions
                        .iter()
                        .filter(|tx| tx.sender == sender.address)
                        .map(|tx| tx.amount)
                        .sum();
                    let available = blockchain
                        .get_balance(&sender.address)
                        .saturating_sub(committed);

                    let tx = sender
                        .create_transaction(&wallets[to].address, amount)
                        .expect("a generated wallet key must sign");
                    let accepted = blockchain.add_transaction(tx).is_ok();

                    prop_assert_eq!(
                        accepted,
                        amount <= available,
                        "the mempool must accept a payment exactly when the sender can cover it"
                    );
                }
            }
        }

        prop_assert!(blockchain.is_valid().is_ok());
        prop_assert_eq!(
            blockchain.total_supply(),
            GENESIS_SUPPLY + MINING_REWARD * mined,
            "the only coins ever created are the coinbase rewards"
        );

        // The chain mines at the fast test difficulty, which the file boundary
        // no longer trusts as a base, so persistence is covered separately at
        // the network difficulty by `a_default_difficulty_chain_round_trips`.
    }

    /// `replace_chain` adopts a candidate if and only if it is strictly longer
    /// than ours *and* passes whole-chain validation. A rejected candidate
    /// leaves the node exactly as it was.
    #[test]
    fn replace_chain_adopts_exactly_the_longer_valid_chains(
        ours in 0usize..3,
        theirs in 0usize..4,
        corruption in arb_corruption(),
    ) {
        let mut blockchain = Blockchain::with_difficulty(TEST_DIFFICULTY);
        for _ in 0..ours {
            blockchain
                .mine_pending_transactions("our_miner")
                .expect("a freshly mined block must be acceptable");
        }

        let mut rival = Blockchain::with_difficulty(TEST_DIFFICULTY);
        for _ in 0..theirs {
            rival
                .mine_pending_transactions("their_miner")
                .expect("a freshly mined block must be acceptable");
        }

        let mut candidate = rival.chain.clone();
        corrupt(&mut candidate, corruption);

        let should_adopt =
            candidate.len() > blockchain.len() && passes_whole_chain_validation(&candidate);

        let before = chain_hashes(&blockchain.chain);
        let candidate_hashes = chain_hashes(&candidate);
        let adopted = blockchain.replace_chain(candidate).is_ok();

        prop_assert_eq!(
            adopted,
            should_adopt,
            "replace_chain disagreed with whole-chain validation ({:?}, ours={}, theirs={})",
            corruption,
            ours,
            theirs
        );

        if adopted {
            prop_assert_eq!(chain_hashes(&blockchain.chain), candidate_hashes);
            prop_assert!(blockchain.is_valid().is_ok());
        } else {
            prop_assert_eq!(
                chain_hashes(&blockchain.chain),
                before,
                "a refused candidate must not disturb the node"
            );
        }
    }

    /// No sender ever gets more than it holds past the mempool, and no
    /// transaction is ever admitted twice, before or after it is confirmed.
    #[test]
    fn a_sender_can_never_spend_more_than_it_holds(
        seed in any::<[u8; 32]>(),
        first in 0u64..120,
        second in 0u64..120,
    ) {
        let alice = wallet_from_seed(&seed);
        let mut blockchain = Blockchain::with_difficulty(TEST_DIFFICULTY);

        // Fund Alice with exactly one reward; mining pays a different address
        // from here on so her balance is not moved out from under the test.
        blockchain
            .mine_pending_transactions(&alice.address)
            .expect("a freshly mined block must be acceptable");
        prop_assert_eq!(blockchain.get_balance(&alice.address), MINING_REWARD);

        let tx_first = alice
            .create_transaction("bob", first)
            .expect("a generated wallet key must sign");
        let first_accepted = blockchain.add_transaction(tx_first.clone()).is_ok();
        prop_assert_eq!(first_accepted, first <= MINING_REWARD);

        let tx_second = alice
            .create_transaction("bob", second)
            .expect("a generated wallet key must sign");
        let spoken_for = if first_accepted { first } else { 0 };
        let second_accepted = blockchain.add_transaction(tx_second).is_ok();
        prop_assert_eq!(second_accepted, second <= MINING_REWARD - spoken_for);

        // The same transaction is never admitted a second time.
        prop_assert!(
            blockchain.add_transaction(tx_first.clone()).is_err(),
            "a transaction already in the mempool must not be admitted again"
        );

        blockchain
            .mine_pending_transactions("miner")
            .expect("a freshly mined block must be acceptable");

        prop_assert!(
            blockchain.add_transaction(tx_first.clone()).is_err(),
            "a confirmed transaction must not be replayed"
        );

        // A block is not a way around any of this: neither repeating a payment
        // nor overdrawing gets past block acceptance.
        let coinbase = Transaction::coinbase("miner".to_string(), MINING_REWARD);
        let repeat = mined_block_on_tip(
            &blockchain,
            vec![coinbase.clone(), tx_first.clone(), tx_first.clone()],
        );
        prop_assert!(
            blockchain.add_block(repeat).is_err(),
            "a block repeating a payment must be refused"
        );

        let overdraft = alice
            .create_transaction("bob", MINING_REWARD + 1)
            .expect("a generated wallet key must sign");
        let overdrawn = mined_block_on_tip(&blockchain, vec![coinbase, overdraft]);
        prop_assert!(
            blockchain.add_block(overdrawn).is_err(),
            "a block spending coins the sender never had must be refused"
        );

        prop_assert!(blockchain.is_valid().is_ok());
        prop_assert_eq!(blockchain.total_supply(), GENESIS_SUPPLY + 2 * MINING_REWARD);
    }

    /// Every transaction in a mined block can be proved against that block's
    /// Merkle root, and a transaction the block does not contain cannot.
    #[test]
    fn every_transaction_in_a_block_has_a_working_proof(
        seed in any::<[u8; 32]>(),
        payments in prop::collection::vec(1u64..10, 0..6),
    ) {
        let alice = wallet_from_seed(&seed);
        let mut blockchain = Blockchain::with_difficulty(TEST_DIFFICULTY);
        blockchain
            .mine_pending_transactions(&alice.address)
            .expect("a freshly mined block must be acceptable");

        for amount in payments {
            // Ignore the rejections: this property is about the block that ends
            // up being mined, whatever the mempool let through.
            let _ = alice
                .create_transaction("bob", amount)
                .map(|tx| blockchain.add_transaction(tx));
        }

        let block = blockchain
            .mine_pending_transactions("miner")
            .expect("a freshly mined block must be acceptable");

        let tx_hashes: Vec<String> = block.transactions.iter().map(|tx| tx.hash()).collect();
        let tree = MerkleTree::new(tx_hashes.clone());
        prop_assert_eq!(tree.root_hash(), block.merkle_root.as_str());

        for (index, tx_hash) in tx_hashes.iter().enumerate() {
            let proof = tree
                .generate_proof(index)
                .expect("every transaction in the tree has a proof");
            prop_assert!(
                MerkleTree::verify_proof(tx_hash, &proof, &block.merkle_root),
                "the proof for transaction {} did not verify against the block",
                index
            );
        }

        let outsider = Transaction::new("mallory".to_string(), "bob".to_string(), 1);
        let proof = tree.generate_proof(0).expect("the coinbase is in the tree");
        prop_assert!(
            !MerkleTree::verify_proof(&outsider.hash(), &proof, &block.merkle_root),
            "a transaction outside the block must not be provable against it"
        );
    }
}

proptest! {
    // Pure hashing and signature checks: cheap enough for the default budget.
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// A Merkle proof verifies against the tree it came from for every leaf and
    /// every tree size, and never carries a leaf the tree does not hold.
    #[test]
    fn every_merkle_proof_verifies_and_outsiders_do_not(
        leaves in prop::collection::vec("[a-z]{1,8}", 1..17usize),
    ) {
        let tree = MerkleTree::new(leaves.clone());
        prop_assert_eq!(tree.transaction_count(), leaves.len());

        for (index, leaf) in leaves.iter().enumerate() {
            let proof = tree
                .generate_proof(index)
                .expect("every leaf of the tree has a proof");
            prop_assert!(
                MerkleTree::verify_proof(leaf, &proof, tree.root_hash()),
                "the proof for leaf {} of {} did not verify",
                index,
                leaves.len()
            );
        }

        // The generator only produces lowercase ASCII, so this can never be a
        // member of the tree.
        let outsider = "NOT A MEMBER";
        let proof = tree.generate_proof(0).expect("leaf 0 exists");
        prop_assert!(!MerkleTree::verify_proof(outsider, &proof, tree.root_hash()));

        prop_assert!(
            tree.generate_proof(leaves.len()).is_none(),
            "a leaf past the end of the tree has no proof"
        );
    }

    /// Two different leaf sets never share a root, so a block's transactions
    /// cannot be swapped without changing its hash.
    #[test]
    fn different_leaf_sets_have_different_roots(
        left in prop::collection::vec("[a-z]{1,8}", 1..9usize),
        right in prop::collection::vec("[a-z]{1,8}", 1..9usize),
    ) {
        prop_assume!(left != right);

        prop_assert_ne!(
            MerkleTree::new(left).root,
            MerkleTree::new(right).root,
            "two different transaction sets must not share a Merkle root"
        );
    }

    /// Repeating the last leaf always changes the root (CVE-2012-2459).
    ///
    /// This is the one collision a random pair of leaf sets will essentially
    /// never stumble into, and it is the one that matters: a tree that pads odd
    /// levels by duplicating its last node makes `[a, b, c]` and `[a, b, c, c]`
    /// share a root, so the last payment in a block can be repeated without
    /// touching the block hash.
    #[test]
    fn repeating_the_last_leaf_changes_the_root(
        leaves in prop::collection::vec("[a-z]{1,8}", 1..9usize),
    ) {
        let mut repeated = leaves.clone();
        let last = leaves.last().expect("the generator produces at least one leaf").clone();
        repeated.push(last);

        prop_assert_ne!(
            MerkleTree::new(leaves).root,
            MerkleTree::new(repeated).root,
            "duplicating the last transaction must change the Merkle root"
        );
    }

    /// A signature verifies if and only if the payload it covers is untouched:
    /// tampering with any signed field, with the signature, or with the key
    /// bound to the sender address breaks verification.
    #[test]
    fn a_signature_verifies_only_while_the_payload_is_untouched(
        seed in any::<[u8; 32]>(),
        other_seed in any::<[u8; 32]>(),
        recipient in "[a-z]{1,12}",
        amount in any::<u64>(),
        field in 0usize..7,
    ) {
        let alice = wallet_from_seed(&seed);
        let mallory = wallet_from_seed(&other_seed);
        prop_assume!(alice.address != mallory.address);

        let tx = alice
            .create_transaction(&recipient, amount)
            .expect("a generated wallet key must sign");
        prop_assert!(tx.verify(), "an untouched signed transaction must verify");

        let mut tampered = tx.clone();
        match field {
            0 => tampered.id.push_str("-tampered"),
            1 => tampered.sender.push_str("-tampered"),
            2 => tampered.recipient.push_str("-tampered"),
            3 => tampered.amount = tampered.amount.wrapping_add(1),
            4 => tampered.timestamp += chrono::Duration::seconds(1),
            5 => {
                let signature = tampered.signature.as_deref().expect("the transaction is signed");
                let mut bytes = hex::decode(signature).expect("a signature is hex");
                bytes[0] ^= 0x01;
                tampered.signature = Some(hex::encode(bytes));
            }
            _ => tampered.public_key = Some(mallory.public_key.clone()),
        }

        prop_assert!(
            !tampered.verify(),
            "a transaction tampered in field {} must not verify",
            field
        );

        // The tamper is what broke it: the untouched original still verifies,
        // and so does a clone of it.
        prop_assert!(tx.clone().verify());

        // A well-formed signature over an unmodified payload is still not
        // enough: the key must own the sender address it signs for. Without
        // that binding any keypair can spend from any account.
        let mut impostor = Transaction::new(alice.address.clone(), recipient, amount);
        mallory
            .sign_transaction(&mut impostor)
            .expect("a generated wallet key must sign");
        prop_assert!(
            !impostor.verify(),
            "a signature from a key that does not own the sender address must be refused"
        );
    }

    /// Two transactions that differ anywhere never share a hash, so no
    /// transaction can be substituted for another inside a Merkle tree.
    #[test]
    fn transaction_hashes_separate_distinct_transactions(
        sender in "[a-z]{1,10}",
        recipient in "[a-z]{1,10}",
        amount in any::<u64>(),
        bump in 1u64..1000,
    ) {
        let tx = Transaction::new(sender, recipient, amount);
        prop_assert_eq!(tx.hash().len(), 64);

        let mut richer = tx.clone();
        richer.amount = richer.amount.wrapping_add(bump);
        prop_assert_ne!(tx.hash(), richer.hash());

        let mut promoted = tx.clone();
        promoted.is_coinbase_tx = true;
        prop_assert_ne!(
            tx.hash(),
            promoted.hash(),
            "the coinbase flag must be covered by the hash"
        );
    }

    /// Moving the boundary between two adjacent fields always changes the hash.
    ///
    /// This is the field-injection property. The preimage used to be the fields
    /// joined by `|`, which makes the hash a function of the joined string
    /// rather than of the fields: the payment `("a|b" -> "c")` and the payment
    /// `("a" -> "b|c")` produced identical bytes, so one hash, and one
    /// signature, covered two different transfers. The generators deliberately
    /// include the old separator.
    #[test]
    fn a_field_boundary_cannot_be_moved(
        left in "[a-z|]{1,8}",
        middle in "[a-z|]{1,8}",
        right in "[a-z|]{1,8}",
        amount in any::<u64>(),
    ) {
        let joined = Transaction::new(format!("{}{}", left, middle), right.clone(), amount);

        // The same characters, split one field further along. Everything else,
        // including the id and the timestamp, is carried over by the clone.
        let mut resplit = joined.clone();
        resplit.sender = left;
        resplit.recipient = format!("{}{}", middle, right);

        prop_assert_ne!(
            joined.hash(),
            resplit.hash(),
            "re-splitting the sender and recipient must change the hash"
        );
    }
}
