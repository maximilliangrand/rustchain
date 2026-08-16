# Security policy

RustChain is an educational project. It secures no real value, runs no public network, and
has never been audited. Please do not use it to hold anything you would miss.

That does not make its bugs uninteresting: the point of the project is to get the consensus
rules right, so a report that shows a rule can be broken is exactly the contribution this
repository wants.

## Supported versions

The `master` branch only. There are no releases and no backports.

## What is already known

Read [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md) first. It lists the attack surface and,
honestly, which threats the code does not yet resist, length-based fork choice, an unbounded
and unauthenticated peer layer, an unpriced mempool, plaintext key files. Those are documented
gaps rather than findings; a report that restates one of them is welcome but will be closed as
known.

A finding that is *not* on that list, anything that lets a node be crashed, a balance be
created, a signature be reused, or two honest nodes to disagree about whether a chain is
valid, is worth reporting.

## Reporting a vulnerability

Use GitHub's private reporting: **Security → Report a vulnerability** on
<https://github.com/maximilliangrand/rustchain>. That opens a private advisory visible only to
the maintainer. If private reporting is unavailable, email
[maximgagiev@myg-media.com](mailto:maximgagiev@myg-media.com) with `rustchain` in the subject.

Please do not open a public issue for a consensus or memory-safety bug until it is fixed.

A useful report contains:

- The rule you believe is broken, in one sentence.
- A failing test, a fuzz artifact, or a chain file that demonstrates it. `cargo test` and
  `cargo fuzz run <target> <artifact>` are the two shapes that need no explanation.
- The commit you tested.

## What to expect

- Acknowledgement within 7 days.
- An assessment, confirmed, known, or not a bug, within 14 days.
- A fix on `master` with a regression test naming the attack, and credit in `CHANGELOG.md`
  unless you would rather not be named.

Because nothing is deployed, there is no embargo period to negotiate: the fix and the
disclosure can land together.

## Scope

In scope: everything under `src/`, `tests/` and `fuzz/`, consensus rules, the wire protocol,
transaction and block validation, and any input that can panic a node.

Out of scope: vulnerabilities in dependencies (report those upstream; CI runs `cargo audit`),
attacks that assume an already-compromised host, and the documented gaps in the threat model.
