# Logos Oracle Zone Node — Implementation Report

**Date:** 22 August 2026
**Target:** Logos public testnet (node release `0.2.2`)
**Status:** Live. Channel created, six inscriptions on chain, single-writer property confirmed from ledger state. Finalization pending the node leaving its bootstrap phase.

---

## 1. Summary

A standalone Rust node that implements the write side of the [LON Oracle Zone draft specification][spec] against the real Logos public testnet.

Each oracle node:

1. Derives a `ChannelId` from its own two public keys.
2. Claims that channel by being the first to inscribe into it — which makes it the channel's **sole accredited writer** at the consensus layer, permanently.
3. Publishes price records signed with **BIP-340** (Schnorr over secp256k1) on a fixed heartbeat.

A second mode, `watch`, reads the same channel back and verifies both properties independently: the write permission from ledger state, the attestation from the record itself.

The published price is hardcoded to `9_412_345_000`. That is deliberate — it removes the price source from the loop so the channel mechanics, the single-writer rule and the attestation can be verified end to end on a live network with nothing else moving.

---

## 2. What was built

A new Cargo package, `logos-oracle-node`, in its own workspace:

```
logos-oracle-zone/
├── Cargo.toml            workspace root
├── rust-toolchain.toml
├── logos-blockchain/     the Logos node repo, pinned to 0.2.2 (added at setup)
└── oracle/
    ├── Cargo.toml
    ├── README.md
    ├── .env.example-oracle
    └── src/
        ├── main.rs       CLI entry point
        ├── lib.rs        clap CLI: run / watch / identity / state
        ├── keys.rs       the two keys, channel-id derivation, key files
        ├── record.rs     wire format + BIP-340 sign/verify (+ BIP-340 test vectors)
        ├── node.rs       the publishing loop, channel-ownership guard, checkpoints
        └── watch.rs      the consumer side: follow the channel, verify every record
```

| Command | What it does |
| --- | --- |
| `identity` | Creates both key files if absent; prints the keys and the channel id they derive. |
| `run` | Publishes the channel announcement, then a signed price record every interval. |
| `state` | Reads the channel's ledger state and asserts this node is its sole accredited writer. |
| `watch` | Follows finalized channel messages and verifies each one's BIP-340 signature. |

Dependencies on the Logos side are path dependencies into the pinned submodule: `logos-blockchain-zone-sdk`, `lb-core`, `lb-common-http-client`, `lb-key-management-system-service`, `lb-groth16`.

---

## 3. Design

### 3.1 Two keys, two different jobs

An oracle carries two identities. Conflating them is the easiest way to get this design wrong.

| Key | Curve | Signs | Verified by |
| --- | --- | --- | --- |
| **Channel key** | Ed25519 | The Bedrock `InscriptionOp` | Consensus — every validator |
| **Attestation key** | secp256k1 / BIP-340 | The price record payload | Anyone holding the record |

They answer different questions. The Ed25519 key answers *"may this node write into this channel at all?"* — a question only the chain can settle. The BIP-340 key answers *"did this oracle really say this number?"* — a question a consumer must be able to settle for itself, holding nothing but the ~130 bytes of the record, without trusting the node it read them from.

### 3.2 How single-writer is enforced

Not by this code. By `core/src/mantle/ops/channel/inscribe.rs` in the Logos node:

```rust
// execute(): the channel does not exist yet
.unwrap_or_else(|| ChannelState {
    accredited_keys: Keys::from(self.signer).into(),
    configuration_threshold: 1,
    ..
})
```

```rust
// verify(): the channel already exists
if self.signer != channel.accredited_keys[channel.round_robin(block_slot).0 as usize] {
    return Err(Error::UnauthorizedSigner { .. });
}
```

The *first* inscription on a previously unseen `ChannelId` permanently installs its signer as that channel's only accredited key. Every later inscription signed by anyone else is rejected by every validator. **No `ChannelConfig` operation is needed** — single-writer is the state a channel is born in.

With exactly one accredited key the round-robin is degenerate (index 0, always), so this oracle holds the write turn permanently and never waits for one. Observed on chain as `posting_timeframe: 0`, `posting_timeout: 0`, `tip_sequencer: 0`.

Two consequences the node handles explicitly:

- **Channel ids are claimed first-come.** `ensure_channel_owned()` refuses to start if the channel already exists under a foreign key, rather than publishing transactions that would all be rejected on chain — a failure otherwise invisible from the publish call, because publishing only enqueues.
- **The first inscription is load-bearing**, so the node makes it an announcement carrying both public keys. The log then states, in its own genesis message, which BIP-340 key readers must demand from every record that follows.

### 3.3 Channel-id derivation

```
channel_id = SHA256( SHA256(tag) ‖ SHA256(tag) ‖ ed25519_pk ‖ bip340_xonly_pk )
tag        = "LON/oracle-channel-id/v1"
```

The channel's address is a commitment to *both* of the oracle's keys, so a node that rotates either key lands on a different channel instead of silently continuing under the old identity. Both halves of the pre-image are fixed-width, so no key pair can be re-split to collide with another. `--channel-id` overrides the derivation when targeting an existing channel.

### 3.4 Wire format

Borsh, matching the spec's `{ pair, price, timestamp, writer_pubkey, signature }`:

```
OracleEnvelope
  magic:   b"LON1"                       cheap non-oracle-traffic filter
  version: 1
  message: Announce(OracleAnnounce) | Price(SignedPriceRecord)

SignedPriceRecord
  record:    PriceRecord { pair, price, decimals, timestamp, writer_pubkey }
  signature: [u8; 64]                    BIP-340, detached
```

The signature sits *outside* the signed struct on purpose: the bytes that get hashed are exactly `borsh(PriceRecord)`, with no field to zero out first, so the pre-image is unambiguous.

Borsh is not self-describing, so a foreign payload can decode into nonsense rather than failing. The magic check, the version check and a trailing-byte check make a bad decode loud instead of silent.

### 3.5 What is signed

```
tag = "LON/oracle-price-record/v1"
e   = SHA256( SHA256(tag) ‖ SHA256(tag) ‖ borsh(PriceRecord) )
sig = schnorr_sign(e, attestation_secret_key)      // 64 bytes, R.x ‖ s
```

The BIP-340 tagged hash is what stops a signature produced here from ever being replayed as a signature over some other protocol's 32-byte digest.

Signing uses `sign_schnorr_no_aux_rand` (`aux_rand = 0`), so the same record always produces the same signature. A re-published orphan is byte-identical to the original.

`sign_price_record()` overwrites `writer_pubkey` with the key that actually signs, so a record can never name a key other than its signer.

### 3.6 The trust boundary: what the chain checks, and what it does not

Bedrock verifies exactly three things about an inscription:

- the **Ed25519** signature over the transaction hash,
- `parent == channel.tip_message`,
- `signer == accredited_keys[round_robin(slot)]`.

The payload is `Inscription = UpperBoundedVec<u8, MAX_BYTES>` — an **opaque byte blob** to consensus. No rule looks inside it. Nobody on chain verifies the BIP-340 signature, checks that the price is a number, or checks that `writer_pubkey` matches anything.

That split is deliberate:

| Layer | Guarantees | Enforced by |
| --- | --- | --- |
| Ed25519 + accredited key | *Who may write to this channel* | Consensus, every validator |
| BIP-340 | *Whether the oracle really said this* | Whoever reads the record, off chain |

Putting the attestation on chain would buy nothing: a trustless consumer has to re-verify it anyway, so on-chain verification means paying gas for work that gets repeated. Keeping it off chain buys portability — lift the record out of the log and relay it through a cache, an API or a gossip layer, and it still proves what the oracle said.

The spec's aggregation step (median across N oracle channels) is off chain in the indexer for the same reason. That is why the spec insists the median window be defined by **inscription order or block height, never wall-clock time**: determinism substitutes for consensus, so every indexer derives the same `attested_price`.

### 3.7 What `watch` does

The first two steps of the spec's five-step indexer pipeline:

1. **Signature verification** — BIP-340, against the key named in the record.
2. **Membership validation** — the accredited key comes from *ledger state*; the attestation key comes from the channel's own announcement (or `--expect-writer`, pinned out of band, which closes the trust-on-first-use window). A record with a perfectly valid signature from a *different* oracle is still rejected: a signature that verifies is not the same as a signature that counts.

Steps 3–5 (outlier filtering, quorum detection, median aggregation) only become meaningful across several oracle channels at once and are out of scope for this build.

`ZoneIndexer::follow()` streams from the node's **LIB** stream, not its block stream — it surfaces only finalized messages. This is deliberate: an indexer that attests to non-final data can be reorged into publishing a price that never happened.

---

## 4. Setup

### 4.1 Prerequisites

Debian/Ubuntu, WSL2 included:

```bash
sudo apt update
sudo apt install -y build-essential clang libclang-dev llvm-dev cmake \
                    pkg-config libssl-dev git curl jq unzip
```

`clang`/`libclang` are required for RocksDB and the C bindings; without them the build fails at link time.

### 4.2 Repository

```bash
unzip logos-oracle-zone-standalone.zip
cd logos-oracle-zone

git clone https://github.com/logos-blockchain/logos-blockchain.git
cd logos-blockchain && git checkout 0.2.2 && cd ..
```

**Pin to `0.2.2`.** That is the release the public testnet runs. `master` is not interchangeable — the zone SDK API moved after 0.2.2 (`ZoneSequencer::init` gained a mandatory `FundingConfig`; the `indexer` module was removed).

### 4.3 Build

```bash
cargo test  -p logos-oracle-node     # 13 tests
cargo build -p logos-oracle-node --release
```

If the ZK-circuits build script cannot reach GitHub releases:

```bash
curl -L -o lbc.tar.gz \
  https://github.com/logos-blockchain/logos-blockchain-circuits/releases/download/v0.5.3/logos-blockchain-circuits-v0.5.3-linux-x86_64.tar.gz
tar xzf lbc.tar.gz
export LBC_ROOT_DIR="$PWD/logos-blockchain-circuits-v0.5.3-linux-x86_64"
```

### 4.4 A Logos node on the public testnet

The oracle is a client. It needs its own Logos node to post through.

**Install the tooling.** These are AppImages and must be placed on `PATH`:

```bash
mkdir -p ~/logos-node && cd ~/logos-node

wget https://github.com/logos-co/logos-package-downloader/releases/download/0.2.1/lgpd-x86_64-linux.tar.gz
wget https://github.com/logos-co/logos-package-manager/releases/download/0.2.1/lgpm-x86_64-linux.tar.gz
wget https://github.com/logos-co/logos-logoscore-cli/releases/download/0.2.2/logoscore-x86_64-linux.tar.gz

for f in lgpd lgpm logoscore; do tar -xvf $f-x86_64-linux.tar.gz; done

mkdir -p ~/.local/bin
install -m755 lgpd-x86_64.AppImage      ~/.local/bin/lgpd
install -m755 lgpm-x86_64.AppImage      ~/.local/bin/lgpm
install -m755 logoscore-x86_64.AppImage ~/.local/bin/logoscore

export PATH="$HOME/.local/bin:$PATH"
```

On WSL2 there is no FUSE, so the AppImages will not self-mount. Either install `libfuse2` or set:

```bash
export APPIMAGE_EXTRACT_AND_RUN=1
```

**Install the blockchain module and start the daemon.** These must run *sequentially* — the daemon takes a few seconds to emit `~/.logoscore/client/config.json`, and any client command issued before that fails with `No client config`:

```bash
lgpd download blockchain_module --version 0.2.2 --output ./
lgpm --modules-dir ./modules install --file blockchain_module-0.2.2.lgx

nohup logoscore -m ./modules -D > daemon.log 2>&1 &
sleep 5
logoscore load-module blockchain_module        # expect: Loaded module: blockchain_module
```

**Join the testnet.** These are the testnet bootstrap peers. The `65.108.203.235` set that also appears in the release notes is **devnet** — a different chain with a different faucet:

```bash
logoscore call blockchain_module generate_user_config '{
  "initial_peers": [
    "/ip4/65.109.51.37/udp/3000/quic-v1/p2p/12D3KooWFrouXfmrR4nsLMtE7wu15DoMJ6VtoUtHinREZCvbWHar",
    "/ip4/65.109.51.37/udp/3001/quic-v1/p2p/12D3KooWJRGau8M1rjT7R5e4YYsgdFhsMX35nRDtMwCDjxQkXAHz",
    "/ip4/65.109.51.37/udp/3002/quic-v1/p2p/12D3KooWQXJavMDTRscjauFSgVAB1VLB6Rzpy2uY5SU9Tk7927tb",
    "/ip4/65.109.51.37/udp/50001/quic-v1/p2p/12D3KooWSQc7CcGtvWDPF1yCbBthFnQjprfCVHmfmNDUrSmqQsU1"
  ]
}'

nohup logoscore call blockchain_module start user_config.yaml "" > node.log 2>&1 &
```

`generate_user_config` writes `user_config.yaml`. **Never run it a second time** — it mints new `known_keys`, and the faucet-funded key is lost with them.

`start` is a long-lived call. Backgrounding it can make the *client* return `RPC_FAILED` while the node itself starts correctly; check `daemon.log` for `Received new block` rather than trusting the client's exit code. A second `start` returning `"The node is already running."` is confirmation, not an error.

### 4.5 Funding

```bash
grep -A3 known_keys user_config.yaml
```

Paste one key id into **Destination Public Key (Hex)** at <https://testnet.blockchain.logos.co/web/faucet/>. One request per block — wait for the balance to move before asking again.

```bash
curl -w "\n" http://localhost:8080/wallet/<key>/balance
```

That key becomes `--funding-pk`. The node appends the fee inputs, proves the transfer and returns a funded transaction; its wallet secret never leaves the node. Note that the `funding_pk` field inside `user_config.yaml` is the node's *own* SDP/leader-claim wallet and is unrelated: `/wallet/fund` funds from whatever `known_keys` entry the request names.

Omitting `--funding-pk` builds fee-less transactions, which the chain accepts only while gas prices are zero. Acceptable for a first smoke test, not something to rely on.

---

## 5. Running

```bash
cd logos-oracle-zone

./target/release/logos-oracle-node identity

./target/release/logos-oracle-node run \
  --node-url http://localhost:8080 \
  --funding-pk <funded key> \
  --pair BTC/USD --decimals 8 --interval-secs 30
```

In a second terminal:

```bash
./target/release/logos-oracle-node state --node-url http://localhost:8080
./target/release/logos-oracle-node watch --node-url http://localhost:8080 \
                                         --expect-writer <attestation key>
```

Every flag has an environment-variable equivalent; see `oracle/.env.example-oracle`.

---

## 6. Success criteria

What to look for, in order.

### 6.1 Build

```
test result: ok. 13 passed; 0 failed
```

The suite includes the official [BIP-340 test vectors][bip340] — signing, verification, and the rejection cases (off-curve public key, `has_even_y(R)` false, negated message). A wrong curve, a wrong hash or a too-permissive verifier fails loudly rather than producing signatures nobody else can check.

### 6.2 Node

```bash
logoscore call blockchain_module get_cryptarchia_info | jq -r .result.value | jq .
```

`height` should be climbing. `slot` climbs much faster — Cryptarchia does not produce a block in every slot, so a height/slot ratio of a few percent is normal and does **not** mean the node is behind.

`"mode": "Bootstrapping"` with `"phase": "ProlongedBootstrapPeriod"` is expected for the first hour after start (`prolonged_bootstrap_period: 3600` in the generated config).

### 6.3 Oracle

```
Sequencer ready - publishing every 30s
Published channel announcement (channel genesis)
Published BTC/USD = 94.12345000 (raw 9412345000, t=...) - 1 total
```

`Sequencer ready` arrives even during `Bootstrapping`: on a cold start the backfill range is `[0, network_lib_slot]`, and with LIB still at genesis that range is empty, so backfill completes immediately.

### 6.4 The single-writer proof

```
channel <id> exists
  accredited key [0]: <this node's ed25519 key>
Channel exists and this node is its sole accredited writer
```

Or straight from the node:

```bash
curl -s http://localhost:8080/channel/<channel id> | jq .
```

A single-element `accredited_keys` holding your own key is the whole claim, settled by the ledger rather than by the application.

### 6.5 The attestation proof

Only once the node reaches `Online`, because `watch` reads the LIB stream:

```
Accredited writer(s) on chain: <ed25519 key>
announcement confirms the pinned key <bip340 key>
OK  BTC/USD = 94.12345000 (raw 9412345000, t=..., by <bip340 key>) - 1 verified, 0 rejected
```

At the same moment `run` starts printing `Finalized msg <id> at slot <n>`.

---

## 7. Live run — 22 August 2026

### 7.1 Environment

| Component | Version |
| --- | --- |
| Logos blockchain node module | 0.2.2 |
| `lgpd` / `lgpm` | 0.2.1 |
| `logoscore` | 0.2.2 |
| `logos-blockchain` submodule | tag `0.2.2` |
| ZK circuits | `v0.5.3` |
| Host | WSL2, Ubuntu, x86_64 |

Build verified with rustc 1.95.0 stable: 13 tests pass, clippy clean under the workspace's `pedantic + nursery + restriction + cargo` lint set.

### 7.2 Identity

```
channel id       : b5db26ff232aba10494d5c9f71cb5dcc21575e90dd25b044109574165c8d5e1b
channel key      : 874bbd30849a67a272d0212e2a457d4ad37a98b57f44b8113965cbaa6b5a37c7 (ed25519)
attestation key  : 1e833a66686e350ee25b6375fe349989588e4ea8793604e84c767943d7a1102e (BIP-340 x-only)
hardcoded price  : 9412345000
```

### 7.3 Funding

```json
{"balance":1000000000000,
 "address":"19e583ead78487df908a1b2fbe82dd44438f632d1429a2870fb6dad72fe4080c"}
```

### 7.4 Publishing

```
09:23:41  Sequencer ready - publishing every 30s
09:23:41  ERROR failed to publish announcement: funding failed:
          {"code":500,"message":"Requested wallet state for unknown block: 0x5f9fa9be..."}
09:24:11  Published channel announcement (channel genesis)
09:24:41  Published BTC/USD = 94.12345000 (raw 9412345000, t=1787390681) - 1 total
```

The first-tick error is a race between the sequencer's view of the tip and the wallet service's block-state index: the funding request named a block the wallet had not indexed yet. It cleared on the next tick. The design treats publish failures as recoverable and logs them rather than aborting — for a price feed the next tick carries a fresher record than a retry of the stale one would. Ordering was preserved: announcement first, price second.

### 7.5 Channel state on chain

```json
{
  "accredited_keys": ["874bbd30849a67a272d0212e2a457d4ad37a98b57f44b8113965cbaa6b5a37c7"],
  "configuration_threshold": 1,
  "tip_message": "a465c153d398d84bb83b0d7a94d72bd8fb4255933006a4d4ce119a26febffdc2",
  "tip_slot": 1470317,
  "tip_sequencer": 0,
  "tip_sequencer_starting_slot": 1470271,
  "posting_timeframe": 0,
  "posting_timeout": 0,
  "transfer_threshold": 1
}
```

Reading it field by field:

- `accredited_keys` has exactly one entry and it is this node's Ed25519 key. Any other signer is rejected by consensus as `UnauthorizedSigner`.
- `posting_timeframe: 0` and `posting_timeout: 0` — the round-robin never rotates. The write turn is held permanently.
- `configuration_threshold: 1` — the only signature that can ever accredit another key is this node's.
- `tip_sequencer_starting_slot: 1470271` matches the announcement's slot, confirming that inscription is what created the channel.

### 7.6 Block explorer

Six `INSCRIBE` operations on the channel:

| # | Height | Slot | Content |
| --- | --- | --- | --- |
| 0 | 51658 | 1470271 | announcement |
| 1 | 51659 | 1470287 | price record |
| 2 | 51661 | 1470317 | price record |
| 3 | 51663 | 1470415 | price record |
| 4 | 51665 | 1470457 | price record |
| 5 | 51666 | 1470468 | price record |

The explorer renders each as `"BTC/USD"`. That is incidental rather than designed: it picks up the first readable string in the payload, and `pair` happens to be the first length-prefixed UTF-8 field in the Borsh encoding of `PriceRecord`. The price and the 64-byte signature sit beside it as raw bytes.

### 7.7 What has not been confirmed yet

The node was still in `ProlongedBootstrapPeriod` with `lib_slot: 0` when the session ended, so the inscriptions are **included but not finalized from this node's point of view**. In `cryptarchia-engine`:

```rust
fn lib(cryptarchia) -> Id {
    match cryptarchia.state {
        Bootstrapping => cryptarchia.branches.lib,                       // does not advance
        Online => cryptarchia.branches.nth_ancestor(&local_chain, k).id(),
    }
}
```

LIB is frozen during bootstrap and jumps to `tip - k` the moment `online()` runs. LIB is each node's *own* judgment of irreversibility, not a global flag — nodes that are already `Online` finalized these blocks long ago.

Consequently `watch` produced no output and `run` printed no `Finalized msg` lines. Both open as soon as the node reaches `Online`. This is correct behaviour, not a defect: an indexer that attests to non-final data can be reorged.

---

## 8. Known rough edges

- **First-tick funding race.** Recovers on the next tick, but that costs one interval. An immediate bounded retry on `Requested wallet state for unknown block` would tighten it.
- **Orphan handling is intentionally lossy.** A reorg that orphans an inscription is logged; the next tick publishes a fresh record rather than re-publishing the old one. Correct for a price feed, wrong for a log that must be gap-free.
- **`timestamp` is provenance, not consensus input.** Nothing validates it. Any aggregation built on top must key its window on inscription order or block height, per the spec.
- **Trust-on-first-use without `--expect-writer`.** If the attestation key is not pinned out of band, `watch` learns it from the channel's first message. Pin it whenever the key is known.
- **The node process is session-bound.** Started with `&` in a shell, it dies when the WSL session ends. `nohup` survives a closed terminal but not a full WSL shutdown.
- **Not verified on a fully-synced node.** Everything through §7.6 is confirmed; §6.5 is not.

---

## 9. Next steps

1. Confirm §6.5 once the node reaches `Online` — the last link in the chain from ledger write permission to off-chain signature verification.
2. **Adversarially test the single-writer claim.** Point a second identity at the same `--channel-id`. The application guard should refuse with `ChannelNotOurs`; bypassing that guard should produce `UnauthorizedSigner` on chain. This converts "the code says so" into "the chain behaves so".
3. **Run several oracles.** Each with its own key files, each deriving its own channel. This is the shape the spec assumes — no oracle can censor or reorder another's submissions, because no oracle can write to another's channel.
4. **Build the aggregating indexer.** Follow N channels, apply the remaining pipeline steps (outlier filtering, quorum detection, median), and write `attested_price` to zone state — with the window keyed on block height.
5. **Replace the hardcoded price.** Fetch from ≥2 sources and take the local median, per the spec's oracle-node requirements.

---

## 10. References

- [LON Oracle Zone — Architecture Draft Specification][spec]
- [Logos Oracle Network (LON) — Requirements and Features](https://forum.research.logos.co/t/logos-oracle-network-lon-requirements-and-features/696)
- [logos-blockchain releases][release] — testnet bootstrap peers, faucet, node setup
- [Testnet faucet](https://testnet.blockchain.logos.co/web/faucet/) · [Testnet dashboard](https://testnet.blockchain.logos.co/web/)
- [BIP-340 test vectors][bip340]

[spec]: https://forum.research.logos.co/t/lon-oracle-zone-architecture-draft-specification/698
[release]: https://github.com/logos-blockchain/logos-blockchain/releases/latest
[bip340]: https://github.com/bitcoin/bips/blob/master/bip-0340/test-vectors.csv
