# LON dispute resolution on LEZ

A LEZ program implementing the RFC-244 dispute path, plus a single-node LEZ
chain that runs it — real guest ELF, real RISC Zero zkVM, real cycle counts.

## Run it

```sh
# once — needs the RISC Zero toolchain, run from the workspace root
cargo risczero build --manifest-path methods/guest/Cargo.toml

cargo run --release
```

Without the RISC Zero toolchain, `./build_guest.sh` builds the guest with stock
Rust (`-Z build-std`); it needs a Rust source checkout matching your `rustc`:

```sh
git clone --depth 1 --branch "$(rustc --version | cut -d' ' -f2)" \
  https://github.com/rust-lang/rust.git ~/rustsrc
cd ~/rustsrc && git submodule update --init --depth 1 library/backtrace library/stdarch
RUST_SRC=~/rustsrc/library ./build_guest.sh
```

## The model

A proposer attests a price; the contract stores it unchecked and opens the
dispute window. To dispute, an indexer pushes the round's finalized observations
to LEZ wrapped in **its own** BIP-340 signature and membership proof.

LEZ cannot know what Bedrock actually finalized, so one deliverer is not enough
— it could hand over a set that is entirely valid but *incomplete*, chosen to
move the median. The defence is accumulation from many independent indexers, so
**the quorum counts distinct submitting indexers, not observations**.

Two signature layers → 2N verifications per dispute: each `submit` verifies the
submitter (1 BIP-340 + 1 membership proof) plus every *new* observation it
carries. Already-accumulated observations are skipped. Everything is verified on
arrival; only the price survives into state, the observation is discarded.

```
initialize(membership_root, quorum_n, set_size, decimals)
propose(round, price)      ← optimistic, nothing verified
submit(submission)         ← submitter verified, then each new observation
                             resolution fires inline at N distinct submitters
```

## Parameters

| env var | default | meaning |
|---|---:|---|
| `LON_QUORUM` | 50 | N — distinct indexers needed to resolve |
| `LON_OBSERVERS` | 60 | oracle nodes publishing an observation this round |
| `LON_SET` | 512 | active oracle set size → Merkle depth 9 |
| `LON_BATCH` | 60 | observations per `submit` tx |
| `LON_MEASURE` | 1 | set to 0 to skip cycle measurement |

`LON_QUORUM=6 LON_OBSERVERS=8 LON_SET=32 cargo run --release` is a fast smoke run.

## What the run does

**setup** — `initialize` writes the membership root, N, set size and decimals
into the dispute state PDA.

**round 1 — the dispute succeeds.** The proposer attests a deliberately wrong
price. 50 indexers deliver the 60 finalized observations, the contract recomputes
the median, it does not match, the proposer is marked slashable.

**guards** — two negative tests. A submitter outside the active set is rejected
(`not in the active oracle set`). A submission whose 60 observations all carry
junk signatures is accepted as a transaction but credits **0** observations and
does not move the counter — verification happens on arrival, so junk cannot
occupy a slot.

**round 2 — the happy path.** The proposer attests the correct median, the same
delivery reproduces it, the dispute fails, nothing is slashed.

**round 3 — the subset attack, and it succeeds.** 50 colluding indexers deliver
the 50 highest-priced observations of the 60 that were finalized. Nothing is
forged: every observation is genuinely signed by a registered member and passes
every check. The attack is **omission**. Resolution fires the moment the 50th
distinct indexer speaks, so no honest indexer can put back the 10 missing
observations, and an honest proposer is slashed on the attacker's median.

## Measured

N = 50, 60 observers, active set 512, whole set in one transaction. Budget is
`MAX_NUM_CYCLES_PUBLIC_EXECUTION = 33,554,432`, enforced per public execution
(per transaction) against **user** cycles.

| transaction | cycles | budget |
|---|---:|---:|
| `initialize` | 123,564 | 0.4% |
| `propose` | 186,740 | 0.6% |
| **first delivery** — 60 observations verified | **30,154,708** | **89.9%** |
| repeat delivery — all 60 already counted | 11,991,771 | 35.7% |
| rejected junk delivery — 60 signatures fail | 29,595,814 | 88.2% |

Round total: **111 BIP-340 checks** (51 submitters + 60 observations),
**state 731 bytes**.

Verification cost per observation, isolated (`bench/`):

| workload | with risc0 accelerators | without | speedup |
|---|---:|---:|---:|
| Merkle membership (depth 9) | 102,022 | 176,027 | 1.7× |
| BIP-340 Schnorr verify | 375,131 | 5,626,306 | 15.0× |
| BIP-340 + membership | 390,327 | 5,715,435 | 14.6× |
| ECDSA recover (comparison) | 687,759 | 11,503,665 | 16.7× |

The accelerators come from `[patch.crates-io]` on RISC Zero's `k256`,
`crypto-bigint` and `tiny-keccak` forks. The earlier PoC missed them because
`methods/guest` declared its own `[workspace]` and Cargo only applies `[patch]`
from the root of the graph being built — which is where "only 2 signatures per
transaction" came from. It was a build configuration, not a platform limit.

## Findings for the RFC

**Delivering the whole set in one transaction costs 89.9% of the budget.** The
ceiling is around 66 observations per transaction. Above that an indexer must
split its delivery — which the design allows, since it still counts once toward
the quorum. Splitting halves the peak but pays one submitter check per
transaction:

| observations per `submit` | peak tx | repeat tx | submit txs | BIP-340 checks |
|---:|---:|---:|---:|---:|
| 60 | 30,154,708 (89.9%) | 11,991,771 (35.7%) | 50 | 111 |
| 30 | 15,401,124 (45.9%) | 6,437,718 (19.2%) | 99 | 160 |

**Repeat deliveries cost 11,991,771 cycles and accomplish nothing** — pure
deserialization of observations that are then skipped. Across 49 confirming
indexers that is ~588M wasted cycles per dispute. The fix is a layered scheme: an
indexer that agrees with what has accumulated submits a bare attestation — its
signature and membership proof, no observations — and sends full data only when
it disagrees. Roughly 12M → 500K on 49 of the 50 transactions.

**A junk delivery costs the network 29,595,814 cycles and the attacker nothing.**
It corrupts no state, but until fees exist it is free block space to burn.

**Resolving at N enables the subset attack (round 3).** Two things follow:

* The submitter quorum only defends while the adversary controls **fewer than N
  seats**. The RFC assumes an honest majority, which permits ~250 malicious seats
  out of 500 — far more than 50. So N = 50 does not follow from that assumption.
* The RFC already contains the real defence and contradicts itself: §5 argues an
  honest indexer can present an omitted observation *during the window*, and
  Aggregation step 4 says the median is over all observations in the round, not
  only the first N. Both require resolution to **wait for the window to close**.

Resolving at window close over the accumulated union would close this. It needs
block height, which LEZ exposes through the clock program.

**LEZ verifies authenticity, not provenance.** Every signature checks out, but
the chain has no way to know what Bedrock actually finalized. That is the root
cause of both the subset attack and its sibling, where a single malicious seat
swaps its own observation value — still validly signed by its own key.

## Layout

```
program/            the SPEL program — the dispute contract
methods/guest/      the zkVM entry point; builds to riscv32im-risc0-zkvm-elf
harness/
  lez_node.rs         a single-node LEZ chain on lee::V03State
  main.rs             the driver: oracle set, three rounds, assertions
bench/              isolated cycle benchmark for the verification primitives
build_guest.sh      guest build without the RISC Zero toolchain
```

`harness/src/lez_node.rs` applies every transaction through
`V03State::transition_from_public_transaction` — the same call the sequencer
makes when it builds a block. It verifies transaction signatures, checks nonces,
builds pre-states, **executes the program's RISC-V image in the zkVM**, runs
`validate_execution`, resolves PDA claims and commits the diff. The program id is
the real image id.

Missing relative to a live testnet: Bedrock/DA, block production and finality,
the mempool and its ordering, the RPC and indexer — so network delay, fee
markets and concurrent submitters are out of scope here.

## Open items

**A stalled dispute leaves the window open.** `window_open` clears only on
resolution and `propose` refuses while open, so a quorum that never arrives
stalls the feed. `W_dispute` needs the clock program — the same dependency as
resolving at window close.

**Transactions on one PDA serialize.** Every `submit` writes the same account.
With N = 50 that is 50 transactions inside `W_dispute` = 90 LEZ blocks. Whether
several can share a block needs checking against the sequencer. This is the part
a local run cannot exercise.

**Slashing is a flag**, not a transfer; stake custody lives elsewhere.

## Notes

`methods/guest/Cargo.lock` is pinned to versions the RISC Zero builder image's
rustc (1.88) accepts — `ruint 1.17.0` and `enum-ordinalize 4.3.0` in particular.
`cargo update` inside `methods/guest` pulls newer crates needing rustc 1.89+ and
the Docker build fails; downgrade those two back if it happens.

`thread '<unnamed>' panicked at program/src/lib.rs:...` lines in the output are
expected — that is how a SPEL program signals a rejected transaction from inside
the guest.
