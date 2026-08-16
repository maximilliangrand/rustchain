# RustChain threat model

RustChain is an educational blockchain: ed25519 signatures, proof-of-work, a Merkle
commitment per block, an account-balance ledger, a length-prefixed TCP gossip protocol and
a JSON file for storage. It is not deployed, holds no value, and has no live network.

This document exists so that the difference between "this code implements a blockchain" and
"this code would survive an adversary" is written down rather than assumed. Each threat below
says what the code does today and, where it does nothing, says so plainly. **The gaps are the
point of the document.** A reader should be able to decide, from this file alone, whether a
given attack works against this implementation.

Status keys used throughout:

- **Addressed**, a specific mechanism resists this, and a test pins it.
- **Partial**, the obvious version is blocked, a stronger version is not.
- **Open**, nothing in the code resists this.
- **Accepted**, out of scope by design for an educational chain.

---

## 1. Scope

### What an attacker wants

1. Spend coins they do not own, or spend the same coins twice.
2. Create coins out of nothing.
3. Rewrite confirmed history.
4. Take a node off the network, or feed it a private view of the world.
5. Extract a private key.

### Trust boundaries, every byte that comes from somewhere we do not control

| Boundary | Entry point | Attacker controls |
|---|---|---|
| P2P socket | `network::read_message` → `Node::handle_message` | Every byte, framing included, from any peer that can reach the port |
| Chain file | `Blockchain::from_json` | The whole file, if they can write to it |
| Wallet file | `Wallet::from_json` | The whole file, if they can write to it |
| CLI arguments | `cli::Cli` | Whatever the operator was tricked into typing |

Everything reachable from those four is untrusted input. The library denies
`clippy::unwrap_used`, `expect_used`, `panic` and `unwrap_in_result` at the crate root, so a
panic on attacker bytes is a compile error rather than a discovered outage, and five
`cargo-fuzz` targets cover transaction, block, message, framing and whole-chain decoding.

### Out of scope

Compromise of the machine a node runs on, a malicious operator, side-channel attacks on the
ed25519 implementation (delegated to `ed25519-dalek` 2.x), and supply-chain attacks on
dependencies beyond the `cargo audit` job in CI.

---

## 2. Double-spend

**Within one block, addressed.** `Blockchain::apply_block` is the single definition of what a
block does to the ledger, shared by block acceptance and by whole-chain validation, so the two
cannot disagree. It debits with `checked_sub`, so a sender who cannot cover a spend is a
rejected block rather than a saturating subtraction that would silently mint the difference,
and it inserts every transaction id into a set, so the same transaction cannot appear twice in
one block or twice in the chain.

**In the mempool, addressed.** `add_transaction` subtracts everything already pending from the
same sender before it compares against the balance, so a sender cannot queue two transactions
that are individually affordable and jointly are not.

**By reorganisation: addressed for the time-warp attack, partial otherwise.** The fork-choice
rule is now *heaviest valid chain*. `replace_chain` still requires the candidate to share our
genesis block and to validate block by block from genesis, but it then compares accumulated
work, not length: `total_work` is the saturating sum of `16^difficulty` over the blocks, and a
candidate is adopted only if it carries strictly more work than what we hold. A tie or a
lighter chain loses even when it is the longer one.

This closes the time-warp reorg. With a fixed difficulty, length and work are the same
ordering; with the retarget they are not, and the old length rule let a miner who drove the
difficulty down win a reorg on block count while spending far less work. Two further changes
back this up. Median-time-past (below, §6) bounds a block's timestamp from beneath, so a miner
can no longer backdate blocks to declare a window slow and drop the difficulty at will; and the
genesis/base difficulty is no longer read from the chain file (it is anchored to
`DEFAULT_DIFFICULTY` on load), so a crafted file cannot declare its first retarget window mined
at difficulty 1. A regression test builds a strictly longer, internally valid, but lighter
chain and confirms it is refused.

What remains is the *ordinary* reorg: an attacker with genuinely more work can still rewrite
recent history, and this is the honest-majority assumption of §3, not a bug. Any recipient is
exposed to it for as long as they treat a shallow block as final. Nothing in the code advises a
confirmation depth, and the CLI reports a payment as complete as soon as it is mined once.

---

## 3. Majority hashpower (51%)

**Accepted.** Proof-of-work assumes the honest majority; an attacker with more hashpower than
the rest of the network can reorganise recent history, censor transactions, and double-spend
against anyone who accepts a shallow confirmation. No proof-of-work chain resists this, and
this one is far cheaper to overwhelm than most:

- There is no network. "The rest of the network" is however many people are running `mine`.
- Mining is a CLI command, not something a node does on its own, so honest hashpower is not
  continuously applied.
- The difficulty floor is `MIN_DIFFICULTY = 1`, one leading hex zero: 16 hashes on average.
- Fork choice now counts work rather than blocks (§2), so a long chain of cheap blocks no
  longer substitutes for a majority. What an attacker needs is genuinely more work than the
  honest network applies, which, given the two points above, is still not much.

Selfish mining and block withholding are equally unaddressed. There is no accounting for
uncles, no finality gadget, and no checkpointing.

---

## 4. Eclipse and Sybil attacks on the P2P layer

**Open.** This is the weakest layer of the system.

- **No identity.** A peer is a string like `127.0.0.1:8333`, learned from whatever a peer put
  in the `listen_address` field of its `Version` handshake or listed in reply to `GetPeers`.
  Nothing proves a peer controls the address it advertises, so one host can occupy the peer
  table under any number of names.
- **The peer table is bounded but not managed.** Every address is now validated as a
  `SocketAddr` and the table is capped at `MAX_PEERS = 1024`, so a peer can no longer grow it
  without limit or point the node at a malformed target. What is still missing is eviction,
  scoring and bucketing by network range: once the table is full, honest addresses learned
  later are simply dropped, so a burst of attacker addresses arriving first can still crowd the
  table.
- **Discovery is deliberately narrow.** A node records the peers named on its command line and
  the peers it directly handshakes with, but it no longer auto-dials addresses a peer merely
  advertised through `GetPeers`: that closes the SSRF/reflection vector where one peer feeds the
  node a list of arbitrary hosts to dial. The flip side is that there is no gossip-based
  discovery at all, so an attacker who supplies every configured peer still owns the node's
  view: `sync_with_peer` adopts any *valid* chain that is heavier, and an eclipsed node cannot
  tell a private valid chain from the public one. Authenticated peers, diversity requirements
  and address-book management are the real fix and are not implemented.
- **No transport security.** Messages are plaintext JSON over TCP with no encryption and no
  authentication, so anyone on the path can read, drop, reorder or rewrite them. Validation
  keeps a rewritten message from being *accepted*, but nothing keeps it from being *dropped*:
  an on-path attacker can censor a node silently.
- **Connection slots are first-come.** `MAX_INBOUND_CONNECTIONS = 64` is a global cap with no
  per-address limit, so a single host can hold every slot and lock honest peers out.

What does exist: inbound peers are recorded from the handshake, so propagation is
bidirectional; broadcast snapshots the peer set and releases the lock before dialling, so one
unreachable peer cannot stall the node; and every dial happens in its own task.

---

## 5. Denial of service through malformed or oversized messages

**Partial.**

Addressed:

- **Framing.** A 4-byte big-endian length precedes each message. The length is compared
  against `MAX_MESSAGE_SIZE` (8 MiB) *before* a buffer is allocated, so an announced 4 GiB
  message costs four bytes and a dropped connection.
- **Unrecoverable input ends the connection.** A frame that does not parse leaves the stream
  out of sync by construction, so the peer is dropped instead of resynchronised.
- **Idle and stalled connections.** The whole read is wrapped in a 120-second timeout, which
  covers both an idle peer and a slow-loris trickling a frame one byte at a time.
- **Connection count.** 64 inbound connections, enforced with a semaphore; over the cap the
  accept loop refuses and keeps serving. A failed `accept` logs and continues rather than
  killing the listener.
- **Panic-freedom.** Fuzzed, and enforced by the clippy denials listed in §1.

Open:

- **Memory is 8 MiB × 64 connections** in the worst case, ~512 MiB of buffers, before the
  parsed values are counted. There is no global memory budget.
- **`MAX_TXS_PER_BLOCK` is checked for `NewBlock` only.** A `FullBlockchain` response is
  bounded solely by the 8 MiB frame, so a synchronising node will happily validate whatever
  fits, and, conversely, a chain that grows past 8 MiB can never be served at all. Chunked,
  height-ranged block transfer is the fix; it is not implemented.
- **The mempool is unbounded and free.** There are no transaction fees anywhere in this
  design, so the only limit on submissions is the attacker's own balance. `add_transaction`
  also scans the whole mempool on each insert, which is quadratic in the number of pending
  transactions.
- **No rate limiting or peer banning.** A peer dropped for sending garbage may reconnect
  immediately.

---

## 6. Timestamp manipulation

**Partial, and much narrower than it was.** A block's timestamp now has a median-time-past
lower bound: it must be strictly greater than the median of the previous up to eleven block
timestamps (`MEDIAN_TIME_SPAN`). This is the rule that was missing, and it is what removes the
free hand a miner had over the only input the retarget reads: a single miner can no longer
backdate a block to declare a window slow and walk the difficulty down. An honest block this
node mines is nudged one second past its parent so clock resolution alone never fails it. The
upper bound is unchanged: at most two hours ahead of the local clock.

The residual is the upper bound, measured against the local clock, so a node with a badly wrong
clock disagrees with its peers about what is acceptable. There is no NTP requirement and no
tolerance for peer clock skew beyond the two-hour window. Median-time-past also allows a block
to sit slightly before its parent as long as it is past the window median, which is the
standard rule, not a regression.

Retargeting itself is defended: the required difficulty is derived from the chain and checked
against what the block claims, the claim is inside the hash preimage, and the response to any
window is capped at one step (a factor of 16) within `MIN_DIFFICULTY..=MAX_DIFFICULTY`. The
genesis block is excluded from every window because its timestamp is a fixed constant.

Transaction timestamps are not validated at all. They are inside the signature and the hash,
so they cannot be changed after signing, but any value is accepted.

---

## 7. Replay

**Addressed within one chain.** A signature covers the transaction `id`, and every id
confirmed in the chain lives in a derived `spent_tx_ids` index that is rebuilt by replaying
the blocks, never read from disk. `add_transaction` refuses an id that is already confirmed or
already pending, and `apply_block` refuses one that is already in the chain, so a captured
signature cannot be mined a second time, from the mempool or inside a hand-built block. Both
paths are pinned by tests.

**Open across deployments.** The signed payload carries no network or chain identifier. Every
instance of this code shares one hard-coded genesis block, so there is no notion of a testnet
distinct from a mainnet, and a transaction signed against one deployment is equally valid
against another. The canonical encoding is versioned by its domain tag, which is the place a
network id belongs when there is one.

**Open on the wire.** Nothing authenticates the transport, so a peer's messages can be
recorded and replayed at it later. Consensus-wise this is harmless, a replayed block or
transaction is simply already known, but it is another reason the peer table can be
manipulated (§4).

---

## 8. Signature malleability and hash ambiguity

**Signatures, addressed.** Verification uses `VerifyingKey::verify_strict`, which rejects
non-canonical scalars, small-order keys and non-canonically encoded `R` values. These are
exactly the signatures on which two ed25519 implementations may legitimately disagree, and a
rule two nodes can disagree about is a chain split. Malleating a signature is in any case not
a way to duplicate a payment here: the signature bytes are inside the transaction hash, so a
mutated copy has a different hash and a different Merkle root, while its `id` is unchanged and
therefore still caught by the replay index.

Verification also binds the carried public key to the `sender` address,
`sender == derive_address(public_key)`, so a valid signature from an unrelated key is not
accepted as the sender's, and one keypair cannot hold two disjoint balances.

**Hash ambiguity (field injection), addressed, and it was real.** Every preimage on this
chain is now built by `core::hashing::CanonicalEncoding`: a domain tag first, then each field
as an 8-byte big-endian length followed by exactly that many bytes. Before that:

- The transaction hash and the signing payload joined fields with `|`. The payment
  `("a|b" -> "c")` and the payment `("a" -> "b|c")` produced identical bytes, so one signature
  authorised two different transfers and one hash stood for both.
- The block header concatenated its fields with *no* separator at all, so the header
  (difficulty 1, nonce 23) and the header (difficulty 12, nonce 3) hashed identically, one
  proof-of-work standing for two different claims about how hard the block was.
- Merkle internal nodes concatenated their two children. Fixed-width hex digests made that
  unambiguous in practice, but only because of what the caller happened to pass.

The domain tag additionally keeps a preimage produced in one context from ever being valid in
another: a block header cannot be presented as a signing payload. Unit tests, a property test
over randomly split fields, and the tests listed against each bullet above pin all of this.

**Merkle second-preimage: addressed.** Leaves, internal nodes, the odd-level padding
sentinel and the empty-tree root each hash under their own domain tag, so no leaf can be
presented as an internal node and an empty tree cannot be confused with a one-transaction one.
Odd levels are padded with the constant sentinel rather than by duplicating the last node,
which is CVE-2012-2459: duplication makes `[a, b, c]` and `[a, b, c, c]` share a root, so the
last payment in a block could be repeated without changing the block hash.

---

## 9. Inflation and the coinbase

**Partial.** A block must carry exactly one coinbase transaction and its amount may not exceed
the mining reward; coinbase transactions are refused from the mempool, so the only way to mint
is to mine. Because the coinbase flag and the public key are inside the transaction hash, a
payment cannot be rewritten into a coinbase, which skips signature checks entirely, without
changing the Merkle root and the block hash.

Open:

- **`mining_reward` is chain state, not a constant.** It is a public, serialized field of
  `Blockchain`, so an edited chain file can raise it and the same file's blocks will then
  validate locally. Chain replacement is not affected, `replace_chain` validates the
  candidate against *our* reward, but the file is trusted more than it should be. A consensus
  constant does not belong in the serialized state.
- **No supply schedule.** 50 coins per block forever, no halving, on top of the 1,000,000-coin
  genesis allocation. Total supply is unbounded.
- **No fees**, so miners have no incentive to include transactions and the mempool has no
  economic protection (§5).

---

## 10. Key management and local storage

**Open.** These are operational, not consensus, but they are the gaps most likely to actually
cost someone a key:

- `wallet create` and `wallet import` write the private key as plaintext JSON with default
  file permissions. There is no passphrase, no key derivation, no `0600`.
- `wallet import <key>` takes the private key as a command-line argument, where it lands in
  shell history and in the process table for every user on the machine.
- The chain file is rewritten in place, not written to a temporary file and renamed, and is
  never fsynced. A crash mid-write leaves a truncated chain; the next start refuses it, which
  is the safe failure but is still a loss.
- Nothing locks the chain file, so a node and a concurrent `mine` will overwrite each other's
  updates.

One narrower leak is closed: `Wallet` no longer derives `Debug`, so the private key cannot
reach a log line or a panic message that happens to format a wallet; it renders as
`<redacted>`, and only an explicit `to_json` export writes it out.

The file *contents* are, at least, not trusted: `from_json` validates the whole chain,
rebuilds balances and the spent-id index from the blocks, and no longer reads the base
difficulty from the file, so editing the `balances` map or the declared `difficulty` changes
nothing.

---

## 11. Summary

| # | Threat | Status |
|---|---|---|
| 2 | Double-spend in a block or the mempool | Addressed |
| 2 | Double-spend by reorganisation, time-warp / cheap-block fork | Addressed |
| 2 | Double-spend by reorganisation, ordinary (more-work) reorg | Accepted (see §3) |
| 3 | Majority hashpower | Accepted |
| 4 | Eclipse / Sybil on the P2P layer | **Open** |
| 4 | SSRF / reflection via advertised peers | Addressed |
| 5 | DoS via malformed or oversized messages | Partial |
| 5 | Unbounded mempool, no fees | **Open** |
| 6 | Timestamp manipulation (median-time-past now enforced) | Partial |
| 7 | Replay within a chain | Addressed |
| 7 | Cross-deployment replay (no network id) | **Open** |
| 8 | Signature malleability | Addressed |
| 8 | Hash ambiguity / field injection | Addressed |
| 8 | Merkle second-preimage, CVE-2012-2459 | Addressed |
| 9 | Coinbase inflation | Partial |
| 9 | `mining_reward` readable from the chain file | **Open** |
| 9 | Base difficulty readable from the chain file | Addressed |
| 10 | Plaintext keys, non-atomic writes | **Open** |
| 10 | Private key leaked through `Debug` | Addressed |

The three that would have to close before this were anything but educational, in order: a peer
layer with identity and bounds (§4), a bounded and priced mempool (§5), and encrypted key
storage (§10). Work-based fork choice, the first item on the old list, is now done.

Reporting: see [SECURITY.md](../SECURITY.md).
