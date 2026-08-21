#!/usr/bin/env bash
# Builds the guest ELF for riscv32im-risc0-zkvm-elf.
#
# Two ways to do this. If you have the RISC Zero toolchain installed
# (`curl -L https://risczero.com/install | bash && rzup install`), the normal
# path is enough and you can ignore this script:
#
#     cd methods/guest && cargo risczero build --manifest-path Cargo.toml
#
# This script is the fallback for environments where rzup cannot reach the
# RISC Zero artifact host. It builds the guest with the stock Rust toolchain by
# compiling `std` from source for the zkVM target — the same mechanism
# `risc0-build` uses when `RISC0_RUST_SRC` is set. The rustflags below are
# copied from `risc0_build::encode_rust_flags`.
#
# Requirements:
#   * a checkout of the Rust source matching your rustc version, e.g.
#       git clone --depth 1 --branch "$(rustc --version | cut -d' ' -f2)" \
#         https://github.com/rust-lang/rust.git ~/rustsrc
#       cd ~/rustsrc && git submodule update --init --depth 1 \
#         library/backtrace library/stdarch
#   * RUST_SRC pointing at that checkout's `library` directory
#
# Usage:
#   RUST_SRC=~/rustsrc/library ./build_guest.sh

set -euo pipefail

RUST_SRC="${RUST_SRC:-$HOME/rustsrc/library}"

if [[ ! -f "$RUST_SRC/Cargo.toml" ]]; then
    echo "error: RUST_SRC=$RUST_SRC does not look like a rust 'library' directory" >&2
    echo "       see the header of this script" >&2
    exit 1
fi

cd "$(dirname "$0")/methods/guest"

# `TEXT_START` from risc0-zkvm-platform; the guest is not a kernel.
TEXT_ADDR=0x00200800

export RUSTC_BOOTSTRAP=1                       # allow -Z on a stable toolchain
export __CARGO_TESTS_ONLY_SRC_ROOT="$RUST_SRC" # where cargo finds std's source
export RISC0_FEATURE_bigint2=1                 # enable the k256 bigint2 accelerator
export CFLAGS_riscv32im_risc0_zkvm_elf="-march=rv32im -nostdlib"
export CC="${CC:-/no_risc0_cpp_toolchain_installed}"

export CARGO_ENCODED_RUSTFLAGS=$'-C\x1fpasses=lower-atomic\x1f-C\x1flink-arg=-Ttext='"$TEXT_ADDR"$'\x1f-C\x1flink-arg=--fatal-warnings\x1f-C\x1fpanic=abort\x1f--cfg\x1fgetrandom_backend="custom"'

cargo build --release \
    --target riscv32im-risc0-zkvm-elf \
    -Z build-std=alloc,core,proc_macro,panic_abort,std \
    -Z build-std-features=compiler-builtins-mem

ELF="target/riscv32im-risc0-zkvm-elf/release/lon_sig_accum"
echo
echo "guest ELF: methods/guest/$ELF"
echo "The harness wraps this with the v1compat kernel into a ProgramBinary on"
echo "startup, so 'cargo run' from the workspace root now works."
