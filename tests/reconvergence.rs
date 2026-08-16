//! Multi-node reconvergence over real TCP.
//!
//! The unit tests check the wire protocol a frame at a time and the property
//! tests check fork choice in memory. Neither can say whether the two hold
//! together as a *network*, which is the only claim a blockchain really makes.
//! These tests build one: several nodes, each with its own chain, each bound to
//! a loopback port the OS hands out, talking to each other through the real
//! listener, the real length-prefixed framing, and the real
//! [`Blockchain::replace_chain`] fork choice. Nothing here is mocked.
//!
//! What is covered:
//!
//! - three nodes that mined competing forks in isolation reconverge on the one
//!   heaviest chain, and agree on the same tip hash at the same height;
//! - a node handed a block it cannot attach pulls the history behind it, so a
//!   fork deeper than one block still closes;
//! - a shorter chain is never adopted, whichever direction it arrives from;
//! - a mined block relays across a line of nodes to one the miner has never
//!   heard of.
//!
//! No test uses a fixed port and none sleeps for a fixed time and assumes: the
//! deterministic paths finish before the call that drives them returns, and the
//! gossip paths poll the real chain state until it says what is being waited
//! for, under a deadline that exists only to fail a hung test.

use std::sync::Arc;
use std::time::{Duration, Instant};

use rustchain::core::Blockchain;
use rustchain::network::Node;

/// Low enough that a whole fork mines in milliseconds, high enough that the
/// proof-of-work check is not vacuous.
const TEST_DIFFICULTY: usize = 2;

/// How long a gossip-driven assertion may take before it is called a failure.
///
/// Deliberately generous: it is a deadlock detector, not a measurement. Every
/// wait polls real state and returns the instant that state is right, so this
/// only ever costs anything on a test that was going to fail.
const CONVERGENCE_TIMEOUT: Duration = Duration::from_secs(30);

/// How long to wait between two polls of a node's chain.
const POLL_INTERVAL: Duration = Duration::from_millis(10);

/// A node bound to a loopback port, serving connections in the background.
struct LiveNode {
    /// The node itself, shared with the task serving it.
    node: Arc<Node>,
    /// The address the OS actually gave it, ready to dial.
    address: String,
    /// The accept loop, aborted when this node is dropped.
    server: tokio::task::JoinHandle<()>,
}

impl LiveNode {
    /// Mine `blocks` blocks in isolation, then put the node on the air.
    ///
    /// Every node starts from the same genesis block, so the chains built here
    /// are competing forks of one currency rather than unrelated ledgers,
    /// which is what makes adopting one of them meaningful.
    async fn spawn(blocks: usize, miner: &str) -> LiveNode {
        let mut blockchain = Blockchain::with_difficulty(TEST_DIFFICULTY);
        for _ in 0..blocks {
            blockchain
                .mine_pending_transactions(miner)
                .expect("a freshly mined block extends its own chain");
        }

        // Port 0 asks the OS for a free port: a hard-coded one collides with
        // other tests, with a parallel run, and with whatever else is on the
        // machine. `bind` returns only once the socket is accepting, so there
        // is no window in which a peer could dial and be refused, and it
        // rewrites the node's advertised address to the port it was given.
        let mut node = Node::new(blockchain, 0);
        let listener = node.bind().await.expect("a loopback port");
        let address = node.address.clone();

        let node = Arc::new(node);
        let serving = Arc::clone(&node);
        let server = tokio::spawn(async move {
            let _ = serving.serve(listener).await;
        });

        LiveNode {
            node,
            address,
            server,
        }
    }

    /// A node that has nothing but the genesis block.
    async fn fresh() -> LiveNode {
        Self::spawn(0, "").await
    }

    /// Mine `blocks` blocks without telling anybody, and return the new tip.
    async fn mine_privately(&self, blocks: usize, miner: &str) -> rustchain::core::Block {
        let mut bc = self.node.blockchain.write().await;
        let mut tip = None;
        for _ in 0..blocks {
            tip = Some(
                bc.mine_pending_transactions(miner)
                    .expect("a freshly mined block extends its own chain"),
            );
        }
        tip.expect("at least one block was asked for")
    }

    /// How many blocks this node currently holds.
    async fn height(&self) -> usize {
        self.node.blockchain.read().await.len()
    }

    /// The hash of this node's tip.
    async fn tip(&self) -> String {
        self.node
            .blockchain
            .read()
            .await
            .latest_block()
            .expect("a chain always has a genesis block")
            .hash
            .clone()
    }
}

impl Drop for LiveNode {
    fn drop(&mut self) {
        self.server.abort();
    }
}

/// Wait until every node reports the same tip at `expected_height`, and return
/// the hash they agreed on.
///
/// Gossip is fire-and-forget, so the only honest way to observe it is to watch
/// the chains themselves and stop the moment they say what is expected. The
/// deadline turns a network that never converges into a failed assertion with
/// the disagreement printed, rather than a test that hangs.
async fn wait_for_agreement(nodes: &[&LiveNode], expected_height: usize) -> String {
    let deadline = Instant::now() + CONVERGENCE_TIMEOUT;

    loop {
        let mut observed = Vec::with_capacity(nodes.len());
        for node in nodes {
            observed.push((node.height().await, node.tip().await));
        }

        let (_, first_tip) = &observed[0];
        if observed
            .iter()
            .all(|(height, tip)| *height == expected_height && tip == first_tip)
        {
            return first_tip.clone();
        }

        assert!(
            Instant::now() < deadline,
            "nodes never agreed on one tip at height {}: {:?}",
            expected_height,
            observed
        );

        tokio::time::sleep(POLL_INTERVAL).await;
    }
}

#[tokio::test]
async fn three_forked_nodes_reconverge_on_the_heaviest_chain() {
    // Three nodes mine competing chains in isolation. Same genesis, different
    // miners, so all three tips are genuinely different blocks and only one
    // chain can win.
    let short = LiveNode::spawn(2, "miner-short").await;
    let heaviest = LiveNode::spawn(5, "miner-heaviest").await;
    let middle = LiveNode::spawn(3, "miner-middle").await;

    assert_eq!(short.height().await, 3);
    assert_eq!(heaviest.height().await, 6);
    assert_eq!(middle.height().await, 4);

    let winning_tip = heaviest.tip().await;
    assert_ne!(short.tip().await, winning_tip);
    assert_ne!(middle.tip().await, winning_tip);

    // Wire them together over real sockets, in the order that exercises both
    // directions: the short node dials the heaviest one and has to climb, then
    // the heaviest dials the middle one, which has to climb without ever having
    // asked for anything.
    short
        .node
        .connect_to_peer(&heaviest.address)
        .await
        .expect("the heaviest node is listening");
    heaviest
        .node
        .connect_to_peer(&middle.address)
        .await
        .expect("the middle node is listening");
    middle
        .node
        .connect_to_peer(&short.address)
        .await
        .expect("the short node is listening");

    let agreed = wait_for_agreement(&[&short, &heaviest, &middle], 6).await;
    assert_eq!(
        agreed, winning_tip,
        "the network converged on a chain that was not the heaviest"
    );
}

#[tokio::test]
async fn a_block_that_will_not_attach_pulls_the_missing_history() {
    // Both nodes start on the genesis block and know each other.
    let miner = LiveNode::fresh().await;
    let follower = LiveNode::fresh().await;
    miner
        .node
        .connect_to_peer(&follower.address)
        .await
        .expect("the follower is listening");

    // The miner then runs ahead in private and gossips only its tip, so the
    // follower is handed a block three deep in a history it has never seen.
    // Relaying blocks alone cannot close a gap like this: the block names a
    // parent the follower does not have, and carries nothing else.
    let tip_block = miner.mine_privately(3, "miner-ahead").await;
    assert_eq!(follower.height().await, 1);

    miner.node.broadcast_block(&tip_block).await;

    let agreed = wait_for_agreement(&[&miner, &follower], 4).await;
    assert_eq!(agreed, tip_block.hash);
}

#[tokio::test]
async fn a_shorter_chain_is_never_adopted() {
    // Fork choice has to be a rule rather than a race, in both directions.
    let ahead = LiveNode::spawn(4, "miner-ahead").await;
    let behind = LiveNode::spawn(1, "miner-behind").await;

    let winning_tip = ahead.tip().await;

    // Pulled explicitly, a shorter chain leaves the puller exactly as it was.
    ahead
        .node
        .sync_with_peer(&behind.address)
        .await
        .expect("the shorter node is listening");
    assert_eq!(ahead.height().await, 5);
    assert_eq!(ahead.tip().await, winning_tip);

    // And offered through a handshake, it still loses: the shorter node is the
    // one that moves, even though it was the one dialled.
    ahead
        .node
        .connect_to_peer(&behind.address)
        .await
        .expect("the shorter node is listening");

    let agreed = wait_for_agreement(&[&ahead, &behind], 5).await;
    assert_eq!(agreed, winning_tip);
}

#[tokio::test]
async fn a_mined_block_reaches_a_node_it_was_never_sent_to() {
    // A line, not a clique: the first node never learns the last one's address,
    // so the only way the last node can see the block is the middle node
    // relaying it onward.
    let first = LiveNode::fresh().await;
    let middle = LiveNode::fresh().await;
    let last = LiveNode::fresh().await;

    first
        .node
        .connect_to_peer(&middle.address)
        .await
        .expect("the middle node is listening");
    middle
        .node
        .connect_to_peer(&last.address)
        .await
        .expect("the last node is listening");

    assert!(
        !first.node.peers.read().await.contains(&last.address),
        "the topology is only a line if the first node cannot reach the last"
    );

    let block = first.mine_privately(1, "miner-first").await;
    first.node.broadcast_block(&block).await;

    let agreed = wait_for_agreement(&[&first, &middle, &last], 2).await;
    assert_eq!(agreed, block.hash);
}
