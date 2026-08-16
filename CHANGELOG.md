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

## [0.1.0]

### Added

- Initial release: SHA-256 hashing, Merkle trees, proof-of-work mining,
  ed25519 transaction signing, chain-derived balances, a mempool, TCP peer
  networking, JSON persistence, and a full CLI.
