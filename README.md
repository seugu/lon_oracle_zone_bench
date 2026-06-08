# Logos Oracle Zone (benchmark prototype)

A minimal Logos zone whose indexer verifies **signed price records** and
aggregates them into an attested median — instead of replaying SQL (SQLite
zone) or applying L2 blocks (LEZ). It mirrors the structure of the
`logos-sql-zone` demo.

The point of this prototype is to answer one question:

> How many ECDSA (secp256k1) signature verifications can a zone indexer perform
> per block, and how does that compare to LEZ's on-chain ceiling of ~64 ECDSA
> verifications (32M cycle budget / ~524K cycles per verify)?

If the indexer can verify far more than 64 signatures per heartbeat, then moving
verification off LEZ into a dedicated Oracle Zone removes the small-committee
bottleneck and the Oracle Zone separation is justified.

## Layout

```
common/      PriceRecord (sign/verify), median, aggregation logic — NO SDK dependency
indexer/     - bin "oracle-bench" : STANDALONE benchmark, no node needed
```

> Note: this package is trimmed to the standalone benchmark, which is all you
> need to answer the verification-throughput question. The live `oracle-indexer`
> and `oracle-sequencer` binaries (which require the Logos zone SDK) are kept in
> the full version; they are omitted here so the benchmark builds with zero
> internal dependencies.

## Build & run

No node required. This is the fastest way to get the numbers:

```bash
# default: N = 10
cargo run --release --bin oracle-bench

# match LEZ's theoretical on-chain ceiling
cargo run --release --bin oracle-bench -- --n 64

# sweep a range and print a table
cargo run --release --bin oracle-bench -- --sweep 3,10,50,64,100,500,1000

# average each measurement over more iterations
cargo run --release --bin oracle-bench -- --n 100 --iterations 50
```

Output reports, per N: average verify time (ms), per-signature time (us),
verifications per second, and an extrapolation to a 30s heartbeat, plus a
comparison line against the LEZ 64-verification ceiling.

## Results

Sample run on a developer laptop (secp256k1 ECDSA, 10 iterations per N):

```
Oracle Zone verification benchmark
  curve: secp256k1 ECDSA (k256)
  iterations per N: 10
  deviation bound: 100 bps

       N |    verify (ms) | per-sig (us) |        verif/sec | attested
----------------------------------------------------------------------
       3 |          0.525 |       175.08 |             5712 |      yes
      10 |          0.684 |        68.44 |            14610 |      yes
      50 |          3.579 |        71.58 |            13971 |      yes
      64 |          5.513 |        86.14 |            11610 |      yes
     100 |          8.899 |        88.99 |            11237 |      yes
     500 |         50.066 |       100.13 |             9987 |      yes
    1000 |         92.122 |        92.12 |            10855 |      yes
----------------------------------------------------------------------
total wall time: 3.67 s
```

The steady-state cost settles around ~90 us per signature verification (the
N=3 row is dominated by fixed overhead). At ~11,000 verifications per second,
the indexer can verify roughly **325,000 signatures within a 30s heartbeat** —
about **5,000x** the LEZ on-chain ceiling of ~64 ECDSA verifications per program
execution (32M cycle budget / ~524K cycles per secp256k1 verify).

This is the core result: moving signature verification off LEZ into a dedicated
Oracle Zone removes the small-committee (N <= 64) bottleneck entirely, making a
large, decentralized oracle set feasible.

Only `common` is needed to build `oracle-bench`; if the SDK paths give you
trouble, you can build just the bench by temporarily removing `sequencer` and
the `oracle-indexer` bin from the workspace.

## End-to-end against a node (optional)

Run a local Logos node (port 8080), then:

```bash
# terminal 1 — oracle node publishes 10 signed records per block, once a second
cargo run --release --bin oracle-sequencer -- --records-per-block 10 --interval-ms 1000

# terminal 2 — indexer verifies each block and logs verify time per block
cargo run --release --bin oracle-indexer
```

The indexer log line per block:

```
block: 10 records | 10 verified | 0 bad-sig | 0 outlier | verify_time = X.XXX ms | attested = Some(65003)
```

Vary `--records-per-block` to push the per-block verification load up and watch
`verify_time` scale.

## Knobs

- `--records-per-block N` (sequencer): signatures packed into one block.
- `--n` / `--sweep` (bench): verification count(s) to measure.
- `--deviation-bps` (indexer/bench): outlier filter width in basis points.
- `--min-quorum` (indexer): minimum valid prices to attest a median.

## Notes

- Signing happens outside the timed region in the bench; only verification is
  measured, since verification is the indexer's actual on-chain-equivalent work.
- The block payload format is newline-delimited JSON (one PriceRecord per line),
  matching the SQLite demo's one-statement-per-line convention.
- secp256k1 ECDSA is used to match the LEZ signature benchmark and the 524K
  cycle figure. Swapping to Schnorr is a one-line change in `price.rs` if you
  want to compare.
