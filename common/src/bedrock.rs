//! Mock Bedrock — an in-process stand-in for the Logos base chain.
//!
//! What the real Bedrock gives a zone, and what this mock preserves:
//!   - **Total order**: every inscription gets a monotonically increasing
//!     sequence number; all followers observe the same order.
//!   - **Finality**: once published here, an inscription is final (no reorgs
//!     in the mock). `finalized_at_ms` records when.
//!   - **Replayability**: a follower can fetch the full backlog and then tail
//!     live inscriptions — exactly the `ZoneIndexer::follow()` contract the
//!     SQLite zone demo builds on.
//!
//! What it deliberately does NOT model: consensus latency, reorg windows,
//! channel signatures at the chain layer, fees. Swapping this for the real
//! `logos-blockchain-zone-sdk` sequencer/indexer pair is a transport change;
//! the record format and the aggregation logic stay identical.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;

use crate::price::PriceRecord;

/// One finalized entry on the mock chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Inscription {
    /// Total-order position assigned by Bedrock.
    pub seq: u64,
    /// Finalization time, Unix milliseconds.
    pub finalized_at_ms: u64,
    /// The zone payload (a signed price record).
    pub record: PriceRecord,
}

impl Inscription {
    /// Newline-delimited JSON wire encoding (one inscription per line).
    pub fn to_line(&self) -> String {
        serde_json::to_string(self).expect("Inscription is always serializable")
    }

    pub fn from_line(line: &str) -> Option<Self> {
        serde_json::from_str(line).ok()
    }
}

pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock before epoch")
        .as_millis() as u64
}

/// The mock chain: ordered log + live broadcast.
pub struct MockBedrock {
    log: Mutex<Vec<Inscription>>,
    live: broadcast::Sender<Inscription>,
    next_seq: AtomicU64,
}

impl Default for MockBedrock {
    fn default() -> Self {
        Self::new()
    }
}

impl MockBedrock {
    pub fn new() -> Self {
        let (live, _) = broadcast::channel(4096);
        Self {
            log: Mutex::new(Vec::new()),
            live,
            next_seq: AtomicU64::new(0),
        }
    }

    /// Publish a record: assign the next sequence number, finalize, broadcast.
    /// The Mutex around the log makes (seq assignment, append) atomic, so the
    /// stored order always equals the seq order.
    pub fn publish(&self, record: PriceRecord) -> Inscription {
        let mut log = self.log.lock().expect("bedrock log poisoned");
        let seq = self.next_seq.fetch_add(1, Ordering::SeqCst);
        let ins = Inscription {
            seq,
            finalized_at_ms: now_ms(),
            record,
        };
        log.push(ins.clone());
        // A send error only means "no live subscribers yet" — fine.
        let _ = self.live.send(ins.clone());
        ins
    }

    /// Snapshot of everything finalized so far, in seq order.
    pub fn backlog(&self) -> Vec<Inscription> {
        self.log.lock().expect("bedrock log poisoned").clone()
    }

    /// Subscribe to live inscriptions. Combine with [`backlog`] for full
    /// replay: subscribe FIRST, then read the backlog, then drain the
    /// receiver skipping seqs already seen — that ordering closes the gap
    /// race.
    pub fn subscribe(&self) -> broadcast::Receiver<Inscription> {
        self.live.subscribe()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::price::random_signing_key;

    fn rec(price: u64) -> PriceRecord {
        PriceRecord::signed(&random_signing_key(), "BTC/USDT", price, now_ms())
    }

    #[tokio::test]
    async fn publish_assigns_dense_monotonic_seqs() {
        let b = MockBedrock::new();
        for i in 0..20 {
            let ins = b.publish(rec(65_000_00 + i));
            assert_eq!(ins.seq, i);
        }
        let log = b.backlog();
        assert_eq!(log.len(), 20);
        for (i, ins) in log.iter().enumerate() {
            assert_eq!(ins.seq, i as u64, "backlog must be in seq order");
        }
    }

    #[tokio::test]
    async fn subscribe_then_backlog_loses_nothing() {
        let b = MockBedrock::new();
        b.publish(rec(1));
        b.publish(rec(2));

        // The race-free follow pattern: subscribe first, then snapshot.
        let mut rx = b.subscribe();
        let backlog = b.backlog();
        assert_eq!(backlog.len(), 2);
        let mut last = backlog.last().unwrap().seq;

        b.publish(rec(3));
        let live = rx.recv().await.unwrap();
        assert!(live.seq > last);
        last = live.seq;
        assert_eq!(last, 2);
    }

    #[tokio::test]
    async fn line_roundtrip() {
        let b = MockBedrock::new();
        let ins = b.publish(rec(64_500_00));
        let back = Inscription::from_line(&ins.to_line()).unwrap();
        assert_eq!(back.seq, ins.seq);
        assert!(back.record.verify().is_ok());
    }
}
