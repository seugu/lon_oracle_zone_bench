AI generated code, don't trust only poc purpose

# Logos Oracle Zone — End-to-End Demo

A fully working Oracle Zone modeled on the [`logos-sql-zone`](https://github.com/logos-blockchain/logos-sql-zone)
demo. Where the SQLite zone's indexer replays SQL statements into a local
database, this zone's indexer **verifies signed price records, filters
outliers, and attests a BTC/USDT price into state on a fixed push heartbeat**.

```
50 oracle users ──signed PriceRecord──▶ Sequencer ──▶ Mock Bedrock (total order, finality)
                                                            │
                                                  TCP follow stream (backlog + live)
                                                            │
                                                            ▼
                                                     Single Indexer
                                              every 5 s (push heartbeat):
                                              1. verify all ECDSA signatures
                                              2. mean of verified prices
                                              3. drop records > 5% from mean
                                              4. if ≥ 10 survive → attest mean
                                                            │
                                                            ▼
                                          data/latest.json + data/history.jsonl
```

## Components

| Component | Folder | Role |
|---|---|---|
| **Common** | `common/` | Signed `PriceRecord` (secp256k1 ECDSA, domain-separated digest), round aggregation (verify → mean → 5% outlier band → quorum), mock Bedrock (ordered, finalized inscription log) |
| **Sequencer** | `sequencer/` | Simulates 50 oracle users (6 of them persistent outlier producers), publishes their signed records to the mock Bedrock, serves the TCP follow stream |
| **Indexer** | `indexer/` | Follows the stream (backlog replay + live tail, gap-free), runs the 5 s push rounds, writes attested state |

The mock Bedrock preserves exactly what the real chain gives a zone — total
order, finality, replayability — so swapping it for the real
`logos-blockchain-zone-sdk` sequencer/indexer pair is a transport change only;
the record format and aggregation logic stay identical.

## Prerequisites

* **Rust** (any recent stable; the workspace is pinned to build on 1.75+).

## Build

```bash
cargo build --release --workspace
```

## Run the demo

### Terminal 1 — Sequencer (oracle users + mock Bedrock)

```bash
cargo run --release --bin oracle-sequencer
```

| Flag | Default | Meaning |
|---|---|---|
| `--listen 127.0.0.1:9090` | `127.0.0.1:9090` | Follow-stream listen address |
| `--users 50` | 50 | Total simulated oracle users |
| `--outlier-users 6` | 6 | Users that always report 6–12% off the market |
| `--base-price 6500000` | 65000.00 | Starting BTC/USDT price in cents |
| `--min-interval-ms 800` / `--max-interval-ms 4000` | 800 / 4000 | Per-user submit cadence (randomized) |

Honest users report the shared market price (a slow ±5 bps/s random walk)
plus their own ±0.8% observation noise. Outlier users are always outside the
5% band, so the indexer must reject every one of them.

### Terminal 2 — Indexer (verify, filter, attest, persist)

```bash
cargo run --release --bin oracle-indexer
```

| Flag | Default | Meaning |
|---|---|---|
| `--connect 127.0.0.1:9090` | `127.0.0.1:9090` | Sequencer follow stream |
| `--heartbeat-ms 5000` | 5000 | Push round interval |
| `--quorum 10` | 10 | Minimum surviving records to attest |
| `--outlier-bps 500` | 500 (= 5%) | Outlier band around the round mean |
| `--state-dir ./data` | `./data` | Where `latest.json` / `history.jsonl` go |

Or run both with one command: `./run-demo.sh`

## Expected output (real captured run)

Sequencer:

```
INFO oracle_sequencer: Oracle Zone sequencer starting
INFO oracle_sequencer:   users=50 (outliers=6)  base=65000.00  interval=800..4000ms
INFO oracle_zone_sequencer: Follow server listening on 127.0.0.1:9090
INFO oracle_zone_sequencer: Published seq=0 price=64869.92 signer=02464c0f69…
INFO oracle_zone_sequencer: Published seq=1 price=64577.28 signer=03139382e7…
INFO oracle_zone_sequencer: Published seq=2 price=65403.18 signer=0211077b91…
...
```

Indexer (one line per 5 s round — note the outliers being cut every round):

```
INFO oracle_indexer: Connected, following inscription stream
INFO oracle_indexer: round 1: ATTESTED BTC/USDT = 65050.43 | received=113 verified=113 bad_sig=0 outliers=13 survivors=100 | verify=14.269 ms | state -> ./data/latest.json
INFO oracle_indexer: round 2: ATTESTED BTC/USDT = 65049.12 | received=108 verified=108 bad_sig=0 outliers=12 survivors=96 | verify=13.106 ms | state -> ./data/latest.json
INFO oracle_indexer: round 3: ATTESTED BTC/USDT = 65081.35 | received=106 verified=106 bad_sig=0 outliers=10 survivors=96 | verify=12.249 ms | state -> ./data/latest.json
```

When the quorum is not met, nothing is written (run with `--users 4` to see it):

```
INFO oracle_indexer: round 1: quorum NOT met (8 valid < 10) | received=10 bad_sig=0 outliers=2 | verify=1.206 ms | state unchanged
```

## Attested state format

`data/latest.json` (overwritten every attested round; `history.jsonl` appends
one line per round):

```json
{
  "round": 3,
  "pair": "BTC/USDT",
  "attested_price": 6508135,
  "attested_price_human": "65081.35",
  "survivors": 96,
  "verified": 106,
  "rejected_sig": 0,
  "rejected_outlier": 10,
  "verify_ms": 12.25,
  "finalized_at_ms": 1781039687794
}
```

Any party running this indexer against the same inscription stream
reconstructs the same attested history — aggregation is deterministic given
the ordered inputs, which is why (exactly as in the SQLite demo) **one
indexer suffices**; more indexers add availability, not security.

## Tests

```bash
cargo test --workspace --release
```

17 tests cover:

* **Crypto** (`common/src/price.rs`): sign/verify roundtrip; tamper of every
  signed field fails; signatures are not transplantable between keys; JSON
  wire roundtrip preserves validity.
* **Aggregation** (`common/src/aggregate.rs`): quorum met with outliers
  filtered (±8% cut, attested within 0.5% of market); no attestation below
  quorum; outliers can never rescue a quorum; bad signatures never count;
  symmetric negative outliers; empty round is a clean no-op.
* **Ordering** (`common/src/bedrock.rs`): dense monotonic sequence numbers;
  the subscribe-then-backlog pattern loses nothing; line encoding roundtrip.
* **End-to-end** (`indexer/tests/e2e.rs`): full in-process pipeline
  (users → Bedrock → backlog → round → attestation); quorum blocking the
  state write; and the **real TCP path** — backlog replay plus a live
  inscription arrive gap-free, in order, and attest.

## Design notes

* **Crypto**: secp256k1 ECDSA via `k256` (RFC 6979 deterministic nonces),
  matching the LEZ signature benchmark for apples-to-apples comparisons. The
  signed digest is domain-separated (`LON-ORACLE-PRICE-V1`) and length-prefixed,
  so signatures cannot be replayed across protocols or reinterpreted across
  field boundaries. Each record carries a random 16-byte nonce.
* **Mean vs median**: the 5% outlier band is computed around the **mean** of
  verified prices, per the demo spec. The mean is draggable by coordinated
  outliers before they are filtered; with a minority of outliers and a 5% band
  it behaves correctly (tests pin this down), but a production zone should use
  a median-based provisional reference.
* **Push windows**: rounds window records by arrival within the heartbeat.
  Deterministic replay across independent indexers should window by Bedrock
  sequence/height instead of wall-clock — a straightforward change once the
  real chain provides block heights.
* **Throughput context**: the indexer verifies a 100+ record round in ~13 ms.
  The earlier standalone benchmark measured ~11,000 verifications/second
  (~325k per 30 s heartbeat) — roughly 5,000× the LEZ on-chain ceiling of
  ~64 ECDSA verifications per program execution, which is the quantitative
  case for the Oracle Zone separation.
