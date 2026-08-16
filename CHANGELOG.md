# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

Hardening pass taking RustChain from a working demo to something that can be
audited: the consensus holes found in review are closed, and the repository now
enforces its own quality bar on every push.

### Added

- Continuous integration (`.github/workflows/ci.yml`) running formatting,
  clippy with warnings denied, the test suite, a release build, and a
  `cargo audit` advisory check on every push and pull request.
- `CHANGELOG.md` and a `LICENSE` file, so the MIT badge the README already
  carried now points at real text.
- A declared minimum supported Rust version (`rust-version = "1.90"`).
- Merkle inclusion proofs, and a spent-transaction-id index consulted by both
  the mempool and block validation.
- Crate-level `deny(clippy::unwrap_used, expect_used, panic, unwrap_in_result)`
  on both the library and the binary, so the compiler now enforces that no
  code path reachable from a peer message, a stored chain or a wallet file can
  abort the process. Tests keep an explicit `cfg(test)` allow.
- `BlockchainError::EmptyChain`, for the paths that need a chain tip.
- Property-based tests (`tests/properties.rs`, using `proptest`) over the
  invariants the chain rests on: a mined chain stays valid and conserves coins,
  `replace_chain` adopts a candidate exactly when it is longer *and* valid, a
  sender can never commit more than it holds, every Merkle proof verifies
  against its own root, and a signature verifies only while its payload is
  untouched. Each was checked by breaking the production line it guards.
- A Criterion benchmark suite (`benches/core.rs`, registered as a
  `harness = false` bench target) over the four costs that decide how a node
  behaves: block header hashing, ed25519 signing and verification, Merkle tree
  construction from 1 to 10,000 leaves, and proof-of-work, both the raw
  hash-attempt rate and full mining at difficulties 1 through 4. Each mining
  benchmark averages over a pool of distinct headers, because a single block is
  one draw from a geometric distribution rather than the expected work. A CI job
  compiles the suite (`cargo bench --no-run`); timings from a shared runner
  would be noise.
- A measured "Performance" table in the README, replacing figures that had never
  been run.
- A `cargo-fuzz` harness (`fuzz/`) with five targets covering every byte the
  node takes from somewhere it does not control: `Transaction` and `Block`
  deserialization, `Message` decoding, the length-prefixed framing in
  `read_message`, and `Blockchain::from_json`. Checked-in seed corpora in
  `fuzz/seeds/` and a 60-second-per-target smoke job in CI.
- `docs/THREAT-MODEL.md`: the attack surface of this design, double-spend,
  majority hashpower, eclipse and Sybil attacks on the peer layer, DoS through
  malformed or oversized messages, timestamp manipulation, replay, signature
  malleability, hash ambiguity, inflation and key storage, with what the code
  does about each, and where it does nothing, an admission rather than a
  silence. `SECURITY.md` carries the disclosure policy.
- `core::hashing::CanonicalEncoding`, the one encoding this chain hashes and
  signs: a domain tag, then every field as an 8-byte big-endian length followed
  by exactly that many bytes.
- `#![warn(missing_docs)]` at the crate root, and the doc comments it asked for.
- Proof-of-work difficulty retargeting. Every `RETARGET_INTERVAL` (10) blocks the
  wall-clock span of the window that just closed is compared with
  `TARGET_BLOCK_TIME_SECS` (60) per block interval: more than 2x too fast raises
  the difficulty one step, more than 2x too slow lowers it one step, otherwise a
  block inherits its parent's. One step is one leading hex zero, a factor of 16
  in work, so the quantisation is itself the per-retarget clamp, stricter than
  Bitcoin's 4x limit. The result is held within `MIN_DIFFICULTY` (1) and
  `MAX_DIFFICULTY` (32), and genesis is excluded from every window because its
  timestamp is a determinism constant rather than a mining time.
- Peer-driven reconvergence. `Node::reconverge` pulls every known peer's chain
  and adopts the longest valid one, routed through the same `replace_chain` that
  already decided fork choice. It is triggered by a `NewBlock` at or beyond our
  tip that will not attach, not attaching is the signal that the missing
  history is ours to fetch, and by a `Version` announcing a greater height, on
  both the listening and the dialling side. `Node::bind` is split out of
  `Node::start` so a node given port 0 learns and advertises the port it was
  actually assigned instead of announcing `:0`.
- `tests/reconvergence.rs`: multi-node fork resolution over real TCP. Two or
  three nodes on OS-assigned loopback ports, the real listener and the real
  length-prefixed framing, no mocks and no fixed ports. Forked nodes reconverge
  on one tip hash at one height, a shorter chain loses from either direction, an
  unattachable block pulls the history behind it, and a mined block relays to a
  node the miner has never heard of. Waits poll real chain state under a
  deadline rather than sleeping.

### Changed

- Applied `rustfmt` to the whole tree once, so the new format gate starts from
  a clean baseline and later diffs carry no formatting noise.
- `Blockchain::latest_block` returns `Option<&Block>` instead of panicking on
  an empty chain. `chain` is a public field, so a chainless `Blockchain` is a
  value a caller can hand us; answering `None` beats aborting the node.
- Block application is a single function shared by block acceptance and
  whole-chain validation, working over a balance index derived from the chain
  instead of read from disk.
- `mine_pending_transactions` returns a `Result` rather than logging a failure
  and reporting success.
- The P2P protocol uses length-prefixed framing; the accept loop survives a
  failed accept, connections are bounded and time out, and broadcasts no longer
  hold the peer lock across a connect.
- Signatures are checked with `verify_strict`, which also refuses small-order
  keys and non-canonical `R` and `A` encodings. Those are the signatures two
  ed25519 implementations may legitimately disagree about, and a rule two nodes
  can disagree about is a chain split.
- Every hash preimage moved to the canonical encoding, which **changes every
  hash**: block hashes, transaction hashes, Merkle roots and signing payloads
  are all different from 0.1.0. Pre-1.0 with no live network, so no migration
  path is provided; an existing `blockchain.json` will no longer validate.
- The balance map is described as what it is, an account ledger, one balance
  per address, instead of "UTXO simplified". This chain has no unspent outputs.
- A block records the difficulty it was mined at, and that value is part of the
  hash preimage, so it cannot be relabelled after the fact. Block acceptance and
  whole-chain validation both re-derive the required difficulty from the chain
  prefix and reject a block whose claim does not match; mining uses the same
  derivation rather than the node's setting. `Blockchain::difficulty` is kept as
  the chain's *starting* difficulty, so `with_difficulty` and `--difficulty`
  keep working and chains shorter than one retarget interval are unaffected.

### Fixed

- Merkle padding duplicated the last node on odd levels (CVE-2012-2459), so
  `[a, b, c]` and `[a, b, c, c]` shared a root. Odd levels are padded with a
  sentinel in its own hash domain, and repeated transaction ids are rejected.
- `Transaction::hash()` omitted `is_coinbase_tx` and `public_key` from the
  preimage, letting a payment be rewritten into a coinbase (which skips
  signature checks) without changing any hash.
- Signatures were verified against an address rather than the signer's public
  key, and the signed payload excluded the transaction id, so one signature
  paid forever.
- The genesis block depended on a random UUID and the wall clock, so no two
  nodes shared a root, and `replace_chain` adopted any genesis a peer sent.
- `pending_transactions` was `#[serde(skip)]`, so the documented
  create -> mine -> confirm workflow silently discarded every transaction.
- `Wallet::from_private_key` and several display paths panicked on untrusted
  input; they now return errors or truncate on character boundaries.
- `Block::total_value` aborted the process on any block whose amounts summed
  past `u64::MAX`, a block is deserialized before anything says its amounts are
  affordable. Found by `cargo fuzz run block_deserialize`; both it and
  `Blockchain::total_supply` now saturate.
- Field injection in every preimage the chain hashed. The transaction hash and
  the signing payload joined their fields with `|`, so the payment
  `("a|b" -> "c")` and the payment `("a" -> "b|c")` produced identical bytes:
  one hash and one signature covering two different transfers. The block header
  concatenated its fields with no separator at all, so (difficulty 1, nonce 23)
  and (difficulty 12, nonce 3) hashed identically, one proof-of-work standing
  for two different claims about how hard the block was. Merkle internal nodes
  concatenated their children, unambiguous only because of what the caller
  happened to pass. All five preimages are now length-prefixed and
  domain-separated.

## [0.1.0]

### Added

- Initial release: SHA-256 hashing, Merkle trees, proof-of-work mining,
  ed25519 transaction signing, chain-derived balances, a mempool, TCP peer
  networking, JSON persistence, and a full CLI.
