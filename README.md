# logos-oracle-zone

A standalone Logos **Oracle Zone** node: one oracle, one channel, one writer.

The node claims a Bedrock channel derived from its own keys, becomes that
channel's sole accredited writer by being the first to inscribe into it, and
publishes **BIP-340**-signed price records there. A second mode, `watch`, reads
the channel back and verifies both the on-chain write permission and the
off-chain attestation.

The design, the wire format and the full public-testnet runbook are in
[`oracle/README.md`](oracle/README.md). This file is only about getting the
tree into a buildable state.

---

## Layout

```
.
├── Cargo.toml           workspace root
├── rust-toolchain.toml
├── logos-blockchain/    the Logos node repo, pinned to 0.2.2  <- you add this
└── oracle/              the oracle crate
```

`oracle` is a Cargo *package*, not a self-contained program: it links against
`lb-core`, `lb-common-http-client`, `lb-key-management-system-service`,
`lb-groth16` and `logos-blockchain-zone-sdk` by path. So `logos-blockchain/`
has to be there before anything builds.

## 1. Add the Logos blockchain source

Pin it to **0.2.2** — the release the public testnet runs. `master` is not
interchangeable: the zone SDK API moved after 0.2.2 (`ZoneSequencer::init`
gained a mandatory `FundingConfig`, the `indexer` module was removed).

Either as a plain clone:

```bash
git clone https://github.com/logos-blockchain/logos-blockchain.git
cd logos-blockchain && git checkout 0.2.2 && cd ..
```

or, if you want this tree to be a git repo of its own, as a submodule — a
`.gitmodules` entry is already here:

```bash
git init
git submodule add https://github.com/logos-blockchain/logos-blockchain.git logos-blockchain
cd logos-blockchain && git checkout 0.2.2 && cd ..
git add . && git commit -m "Oracle Zone node"
```

## 2. Build

Debian/Ubuntu (WSL included) needs a C toolchain for RocksDB and the C
bindings:

```bash
sudo apt install -y build-essential clang libclang-dev llvm-dev cmake \
                    pkg-config libssl-dev git curl jq
```

Then:

```bash
cargo test  -p logos-oracle-node     # 13 tests, incl. the official BIP-340 vectors
cargo build -p logos-oracle-node --release
```

If the circuits build script cannot reach GitHub releases, fetch the artifact
by hand and point `LBC_ROOT_DIR` at it:

```bash
curl -L -o lbc.tar.gz \
  https://github.com/logos-blockchain/logos-blockchain-circuits/releases/download/v0.5.3/logos-blockchain-circuits-v0.5.3-linux-x86_64.tar.gz
tar xzf lbc.tar.gz
export LBC_ROOT_DIR="$PWD/logos-blockchain-circuits-v0.5.3-linux-x86_64"
```

## 3. Run

```bash
./target/release/logos-oracle-node identity   # keys + the channel id they derive
./target/release/logos-oracle-node run   --funding-pk <node wallet key>
./target/release/logos-oracle-node state                 # who owns the channel, on chain
./target/release/logos-oracle-node watch --expect-writer <attestation key>
```

Joining the public testnet, funding a node and reading the output:
[`oracle/README.md`](oracle/README.md). `oracle/.env.example-oracle` has every
setting as an environment variable.

---

## Note on `exclude = ["logos-blockchain"]`

The workspace root carries:

```toml
[workspace]
members = ["oracle"]
exclude = ["logos-blockchain"]
```

Cargo resolves a package to the **outermost** workspace root above it. Without
`exclude`, every `{ workspace = true }` inside `logos-blockchain/` would look
up this file's `[workspace.dependencies]` table instead of the submodule's own,
and the build would fail as soon as the submodule gained a dependency this file
does not mirror:

```
error inheriting `lb-blake2btree` from workspace root manifest's
`workspace.dependencies.lb-blake2btree`
```

`exclude` hands those crates back to their own manifest, which is always in
sync with them. Path dependencies keep working, and there is still one lock
file.
