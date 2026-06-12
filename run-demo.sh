#!/usr/bin/env bash
# Convenience launcher: starts the sequencer in the background, the indexer in
# the foreground, and tears both down on Ctrl-C.
set -euo pipefail

cargo build --release --workspace

./target/release/oracle-sequencer "$@" &
SEQ_PID=$!
trap 'kill $SEQ_PID 2>/dev/null || true' EXIT INT TERM
sleep 1

./target/release/oracle-indexer
