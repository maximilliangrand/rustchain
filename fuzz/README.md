# Fuzzing RustChain

Every byte a node acts on comes from somewhere it does not control: a TCP peer,
or a chain file on disk. These targets exist to prove that no such input can
panic the process, the guarantee the `#![deny(clippy::panic, clippy::unwrap_used,
clippy::expect_used)]` in `src/lib.rs` states for the code we write, checked
against inputs nobody wrote.

## Targets

| Target | Entry point | What it covers |
| --- | --- | --- |
| `transaction_deserialize` | `serde_json` → `Transaction` | hashing and ed25519 verification over attacker-chosen hex, key bytes and amounts |
| `block_deserialize` | `serde_json` → `Block` | block hashing, proof-of-work checking, Merkle root recomputation, transaction verification |
| `message_decode` | `serde_json` → `Message` | every wire message variant, including its block and transaction payloads |
| `message_frame` | `read_message` | the 4-byte length prefix: truncated frames, oversized announcements, several messages pipelined into one buffer |
| `chain_import` | `Blockchain::from_json` | the on-disk format and the full validation path, genesis check, per-height difficulty retarget, proof-of-work, balance replay |

## Running

Requires nightly and [`cargo-fuzz`](https://github.com/rust-fuzz/cargo-fuzz):

```sh
rustup toolchain install nightly
cargo install cargo-fuzz
```

Build every target without running one:

```sh
cargo +nightly fuzz build
```

Run a target, seeded from the checked-in corpus in `fuzz/seeds/`. Without the
seeds a run spends nearly all of its budget failing to produce well-formed JSON
and never reaches the interesting code:

```sh
mkdir -p fuzz/corpus/block_deserialize
cargo +nightly fuzz run block_deserialize \
    fuzz/corpus/block_deserialize fuzz/seeds/block_deserialize \
    -- -max_total_time=60
```

The first corpus directory is where libFuzzer writes what it discovers;
`fuzz/seeds/` is read-only input. Both `fuzz/corpus/` and `fuzz/artifacts/` are
gitignored.

A crash lands in `fuzz/artifacts/<target>/`. Replay it with:

```sh
cargo +nightly fuzz run <target> fuzz/artifacts/<target>/crash-<hash>
```

Anything the fuzzer finds should end up as a unit test next to the code that
was wrong, not only as a corpus file, see `total_value_saturates_instead_of_overflowing`
in `src/core/block.rs`, which is exactly that.

## Harness notes

`block_deserialize` clamps the block's claimed difficulty to `MAX_DIFFICULTY`
before calling `verify_hash(Some(..))`. `difficulty` is a `usize` on the wire and
`verify_hash` materialises a target string of that length, but no real caller
reaches it unclamped: `check_block_structure` compares the claim against the
difficulty the retarget rules demand, never more than `MAX_DIFFICULTY`, and
rejects the block before hashing it. Fuzzing it unclamped would only report an
allocation the node cannot be made to perform.

## CI

The `fuzz` job in `.github/workflows/ci.yml` builds all targets and runs each one
for 60 seconds against the checked-in seeds, so a regression that panics on
obvious input fails the pipeline. It is a smoke test, not a campaign, long runs
belong on a machine that can keep a corpus between them.
