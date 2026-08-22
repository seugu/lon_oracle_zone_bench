# Logos Oracle Zone node

One oracle node, one channel, one writer.

The node derives a `ChannelId` from its own keys, claims that channel by being
the first to inscribe into it — which makes it the channel's **sole accredited
writer** at the consensus layer — and then publishes price records signed with
**BIP-340** (Schnorr over secp256k1). A second binary mode, `watch`, reads the
same channel back off chain and verifies both properties.

This is built to run against the **real Logos public testnet**, not a local
devnet. The runbook below is the whole path from nothing to a verified record
on chain.

---

## 1. The design in one page

### Two keys, two different jobs

| Key | Curve | Signs | Enforced by |
| --- | --- | --- | --- |
| **Channel key** | Ed25519 | The Bedrock `InscriptionOp` | Consensus (`InscriptionOp::verify`) |
| **Attestation key** | secp256k1 / BIP-340 | The price record payload | Anyone holding the record |

They answer different questions. The Ed25519 key answers *"may this node write
into this channel at all?"* — a question only the chain can settle. The BIP-340
key answers *"did this oracle really say this number?"* — a question a consumer
must be able to settle for itself, holding nothing but the 100-odd bytes of the
record, without trusting the node it read them from.

### How single-writer is enforced

Not by this code. By `logos-blockchain/core/src/mantle/ops/channel/inscribe.rs`:

```rust
// verify(): the channel already exists
if self.signer != channel.accredited_keys[channel.round_robin(block_slot).0 as usize] {
    return Err(Error::UnauthorizedSigner { .. });
}
```

```rust
// execute(): the channel does not exist yet
.unwrap_or_else(|| ChannelState {
    accredited_keys: Keys::from(self.signer).into(),
    configuration_threshold: 1,
    ..
})
```

So the *first* inscription on a previously unseen `ChannelId` permanently
installs its signer as that channel's only accredited key, and every later
inscription signed by anyone else is rejected by every validator. No
`ChannelConfig` operation is needed to get the single-writer property — it is
the default a channel is born with.

With exactly one accredited key the round-robin is degenerate (index 0,
always), so this oracle holds the write turn permanently and never waits for
one.

Two consequences the node handles explicitly:

- Channel ids are claimed first-come. If the channel already exists under
  someone else's key, the node **refuses to start** rather than publishing
  transactions that would all be rejected on chain — a failure that is
  invisible from the publish call, because publishing only enqueues.
- The first inscription is load-bearing, so the node makes it an
  **announcement** carrying both public keys. The log then states, in its own
  genesis message, which BIP-340 key readers must demand from every record that
  follows.

### The channel id

```
channel_id = SHA256( SHA256(tag) || SHA256(tag) || ed25519_pk || bip340_xonly_pk )
tag        = "LON/oracle-channel-id/v1"
```

The channel's address is a commitment to *both* of the oracle's keys, so a node
that rotates either key lands on a different channel instead of silently
continuing under the old identity. Pass `--channel-id` to override.

### The wire format

Per the [LON Oracle Zone draft spec][spec] — Borsh, `{ pair, price, timestamp,
writer_pubkey, signature }`:

```
OracleEnvelope
  magic:   b"LON1"
  version: 1
  message: Announce(OracleAnnounce) | Price(SignedPriceRecord)

SignedPriceRecord
  record:    PriceRecord { pair, price, decimals, timestamp, writer_pubkey }
  signature: [u8; 64]        -- BIP-340, detached
```

The signature sits outside the signed struct on purpose: the bytes that get
hashed are exactly `borsh(PriceRecord)`, with no field to zero out first, so
the pre-image is unambiguous.

What gets signed:

```
tag = "LON/oracle-price-record/v1"
e   = SHA256( SHA256(tag) || SHA256(tag) || borsh(PriceRecord) )
sig = schnorr_sign(e, attestation_secret_key)
```

The BIP-340 tagged hash is what stops a signature made here from ever being
replayed as a signature over some other protocol's 32-byte digest. Signing uses
`aux_rand = 0`, so the same record always produces the same signature and a
re-published orphan is byte-identical to the original.

The published price is **hardcoded**:

```rust
pub const HARDCODED_PRICE: u64 = 9_412_345_000;   // 94.12345000 at 8 decimals
```

That is deliberate for this build: it takes the price source out of the loop so
that the channel, the single-writer rule and the attestation can be verified
end-to-end on a live network without anything else moving.

---

## 2. Prerequisites: a Logos node on the public testnet

The oracle is a *client*. It needs its own Logos node to post transactions
through, and that node needs to be synced to the public testnet. Follow the
[0.2.2 release notes][release] — condensed here.

### 2.1 Install

```bash
# lgpd (downloader), lgpm (package manager), logoscore (core CLI)
#   https://github.com/logos-co/logos-package-downloader/releases/latest
#   https://github.com/logos-co/logos-package-manager/releases/latest
#   https://github.com/logos-co/logos-logoscore-cli/releases/latest

lgpd download blockchain_module --version 0.2.2 --output ./
lgpm --modules-dir ./modules install --file blockchain_module-0.2.2.lgx

logoscore -m ./modules -D &
logoscore load-module blockchain_module
```

### 2.2 Join the testnet

These are the **testnet** bootstrap peers (the `65.108.203.235` set in the
release notes is devnet — different chain, different faucet):

```bash
logoscore call blockchain_module generate_user_config '{
  "initial_peers": [
    "/ip4/65.109.51.37/udp/3000/quic-v1/p2p/12D3KooWFrouXfmrR4nsLMtE7wu15DoMJ6VtoUtHinREZCvbWHar",
    "/ip4/65.109.51.37/udp/3001/quic-v1/p2p/12D3KooWJRGau8M1rjT7R5e4YYsgdFhsMX35nRDtMwCDjxQkXAHz",
    "/ip4/65.109.51.37/udp/3002/quic-v1/p2p/12D3KooWQXJavMDTRscjauFSgVAB1VLB6Rzpy2uY5SU9Tk7927tb",
    "/ip4/65.109.51.37/udp/50001/quic-v1/p2p/12D3KooWSQc7CcGtvWDPF1yCbBthFnQjprfCVHmfmNDUrSmqQsU1"
  ]
}'

logoscore call blockchain_module start user_config.yaml ""
```

Wait for consensus to leave `Bootstrapping` and reach `Online`:

```bash
logoscore call blockchain_module get_cryptarchia_info | jq -r .result.value | jq .
```

Cross-check against the [testnet dashboard](https://testnet.blockchain.logos.co/web/).

### 2.3 Fund the node's wallet

```bash
grep -A3 known_keys user_config.yaml
```

Paste one of those key ids into the **Destination Public Key (Hex)** field at
the [testnet faucet](https://testnet.blockchain.logos.co/web/faucet/). One
request per block — wait for the balance to move before asking again.

```bash
curl -w "\n" http://localhost:8080/wallet/<my_key>/balance
```

That key is what you pass to the oracle as `--funding-pk`. The node appends the
fee inputs, proves the transfer and hands back a funded transaction; its secret
key never leaves the node.

---

## 3. Build

The submodule must be checked out — the oracle compiles against the Logos
blockchain crates directly:

```bash
git submodule update --init --recursive
cargo build -p logos-oracle-node --release
```

Pin the submodule to the release the public testnet runs (**0.2.2** at the time
of writing) so the zone SDK matches the network:

```bash
cd logos-blockchain && git checkout 0.2.2 && cd ..
```

If the circuits build script cannot reach GitHub releases, fetch the artifact
by hand and point `LBC_ROOT_DIR` at it:

```bash
curl -L -o lbc.tar.gz \
  https://github.com/logos-blockchain/logos-blockchain-circuits/releases/download/v0.5.3/logos-blockchain-circuits-v0.5.3-linux-x86_64.tar.gz
tar xzf lbc.tar.gz
export LBC_ROOT_DIR="$PWD/logos-blockchain-circuits-v0.5.3-linux-x86_64"
```

---

## 4. Run the oracle

Look at the identity first — this creates both key files and prints the channel
the node will claim:

```bash
cargo run -p logos-oracle-node --release -- identity
```

```
channel id       : 7f3c...            <- the channel this node will own
channel key      : a91e...  (ed25519)
attestation key  : c204...  (BIP-340 x-only)
hardcoded price  : 9412345000
```

Then run it:

```bash
cargo run -p logos-oracle-node --release -- run \
  --node-url http://localhost:8080 \
  --funding-pk <known_key_from_user_config.yaml> \
  --pair BTC/USD \
  --decimals 8 \
  --interval-secs 30
```

What happens, in order:

1. The channel id is written to `./data/channel.txt` for the watcher.
2. Channel state is queried. If the channel exists under a foreign key, the
   node stops with `ChannelNotOurs` instead of publishing into it.
3. The sequencer backfills the channel's finalized history, then emits `Ready`.
4. The first tick publishes the **announcement** — this creates the channel and
   makes this node its sole accredited writer.
5. Every tick after that publishes a signed price record.
6. Each `BlocksProcessed` event persists a checkpoint to
   `./data/oracle.checkpoint`, so a restart resumes rather than replaying.

Confirm on chain at any point:

```bash
cargo run -p logos-oracle-node --release -- state --node-url http://localhost:8080
```

```
channel <id> exists
  accredited key [0]: a91e...          <- exactly one, and it is ours
  tip message: ...
Channel exists and this node is its sole accredited writer
```

### Fee-less mode

Omitting `--funding-pk` builds fee-less transactions. The chain accepts those
only while gas prices are zero, so it is fine for a first smoke test and not
something to rely on. If inscriptions stop landing, that is the first thing to
check.

---

## 5. Verify from the outside

```bash
cargo run -p logos-oracle-node --release -- watch \
  --node-url http://localhost:8080 \
  --channel-path ./data/channel.txt
```

```
Watching channel 7f3c...
Accredited writer(s) on chain: a91e...
Channel announcement: feed BTC/USD @ 8 decimals, attestation key c204..., channel key a91e...
OK  BTC/USD = 94.12345000 (raw 9412345000, t=1755000000, by c204...) - 1 verified, 0 rejected
```

The watcher runs the first two steps of the spec's indexer pipeline:

1. **Signature verification** — BIP-340, against the key named in the record.
2. **Membership validation** — the accredited key comes from *ledger state*,
   and the attestation key from the channel's own announcement. A record with a
   perfectly valid signature from a different oracle is still rejected: a
   signature that verifies is not the same as a signature that counts.

Outlier filtering, quorum detection and median aggregation are the remaining
three steps and only become meaningful across several oracle channels at once.
When they are added, the median window must be defined by inscription order or
block height — never by the record's `timestamp`, which is provenance, not
consensus input.

Pin the key out of band to close the trust-on-first-use window:

```bash
... watch --expect-writer c204...
```

---

## 6. Configuration

Every flag has an environment variable equivalent.

| Flag | Env | Default |
| --- | --- | --- |
| `--node-url` | `ORACLE_NODE_URL` | `http://localhost:8080` |
| `--node-auth-username` / `--node-auth-password` | `ORACLE_NODE_AUTH_*` | — |
| `--channel-key-path` | `ORACLE_CHANNEL_KEY_PATH` | `./data/oracle-channel.ed25519` |
| `--attestation-key-path` | `ORACLE_ATTESTATION_KEY_PATH` | `./data/oracle-attestation.bip340` |
| `--channel-id` | `ORACLE_CHANNEL_ID` | derived from both keys |
| `--channel-path` | `ORACLE_CHANNEL_PATH` | `./data/channel.txt` |
| `--checkpoint-path` | `ORACLE_CHECKPOINT_PATH` | `./data/oracle.checkpoint` |
| `--pair` | `ORACLE_PAIR` | `BTC/USD` |
| `--decimals` | `ORACLE_DECIMALS` | `8` |
| `--interval-secs` | `ORACLE_INTERVAL_SECS` | `30` |
| `--funding-pk` | `ORACLE_FUNDING_PK` | none (fee-less) |
| `--max-tx-fee` | `ORACLE_MAX_TX_FEE` | `1000000` |
| `--priority-fee` | `ORACLE_PRIORITY_FEE` | `200` |
| `--expect-writer` | `ORACLE_EXPECT_WRITER` | learned from the announcement |

Both key files are written `0600`. They are the node's identity — losing the
Ed25519 key means losing write access to the channel permanently, since no
other key can ever be accredited on it without a `ChannelConfig` operation
signed by the key you lost.

---

## 7. Running several oracles

Give each node its own key files, and each derives its own channel:

```bash
... run --channel-key-path ./data/oracle-b.ed25519 \
        --attestation-key-path ./data/oracle-b.bip340 \
        --channel-path ./data/channel-b.txt \
        --checkpoint-path ./data/oracle-b.checkpoint
```

Each channel stays single-writer. An aggregating indexer then follows N
channels and takes the median across them — which is the point of the
per-oracle-channel design: no oracle can censor or reorder another's
submissions, because no oracle can write to another's channel.

---

## 8. Tests

```bash
cargo test -p logos-oracle-node
```

The suite includes the official [BIP-340 test vectors][bip340] — signing,
verification and the rejection cases — so a wrong curve, a wrong hash or a
too-permissive verifier fails loudly rather than producing signatures nobody
else can check.

[spec]: https://forum.research.logos.co/t/lon-oracle-zone-architecture-draft-specification/698
[release]: https://github.com/logos-blockchain/logos-blockchain/releases/latest
[bip340]: https://github.com/bitcoin/bips/blob/master/bip-0340/test-vectors.csv
