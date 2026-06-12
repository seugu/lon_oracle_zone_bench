//! End-to-end integration tests.
//!
//! `pipeline_in_process` exercises the full data path without networking:
//! users → mock Bedrock (ordering) → backlog → round aggregation → attested
//! price, with outliers present and the quorum exactly satisfied.
//!
//! `tcp_follow_end_to_end` runs the real TCP follow server from the sequencer
//! crate, connects like the indexer does, replays the backlog and a live
//! inscription, and runs a round over what was received — proving the wire
//! path (subscribe-then-backlog, seq dedup, JSON lines) is gap-free.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncBufReadExt as _, BufReader};
use tokio::net::{TcpListener, TcpStream};

use oracle_zone_common::{
    now_ms, random_signing_key, run_round, Inscription, MockBedrock, PriceRecord, RoundConfig,
};
use oracle_zone_sequencer::run_follow_server;

const BASE: u64 = 65_000_00;

fn honest_record(offset_bps: i64) -> PriceRecord {
    let price = (BASE as i128 * (10_000 + offset_bps as i128) / 10_000) as u64;
    PriceRecord::signed(&random_signing_key(), "BTC/USDT", price, now_ms())
}

#[tokio::test]
async fn pipeline_in_process() {
    let bedrock = MockBedrock::new();

    // 12 honest users within ±0.6%, 4 outlier users at ±8%.
    for i in 0..12 {
        bedrock.publish(honest_record((i as i64 % 13) - 6).clone());
    }
    for sign in [1i64, -1, 1, -1] {
        bedrock.publish(honest_record(800 * sign));
    }

    // Indexer view: full ordered backlog.
    let backlog = bedrock.backlog();
    assert_eq!(backlog.len(), 16);
    for (i, ins) in backlog.iter().enumerate() {
        assert_eq!(ins.seq, i as u64, "Bedrock order must be dense and monotonic");
    }

    let records: Vec<PriceRecord> = backlog.into_iter().map(|i| i.record).collect();
    let out = run_round(&records, &RoundConfig::default());

    assert_eq!(out.verified, 16, "all signatures are valid");
    assert_eq!(out.rejected_outlier, 4, "every ±8% record must be filtered");
    assert_eq!(out.survivors, 12);
    let attested = out.attested_price.expect("quorum of 10 met by 12 survivors");
    let dev_bps = attested.abs_diff(BASE) as u128 * 10_000 / BASE as u128;
    assert!(dev_bps <= 60, "attested within 0.6% of market, got {dev_bps} bps");
}

#[tokio::test]
async fn quorum_blocks_state_write_in_pipeline() {
    let bedrock = MockBedrock::new();
    // Only 8 honest (below quorum 10) + 5 loud outliers.
    for i in 0..8 {
        bedrock.publish(honest_record((i as i64 % 5) - 2));
    }
    for _ in 0..5 {
        bedrock.publish(honest_record(1_000)); // +10%
    }
    let records: Vec<PriceRecord> = bedrock.backlog().into_iter().map(|i| i.record).collect();
    let out = run_round(&records, &RoundConfig::default());
    assert_eq!(out.rejected_outlier, 5);
    assert_eq!(out.survivors, 8);
    assert!(
        out.attested_price.is_none(),
        "8 survivors < quorum 10 → no attestation"
    );
}

#[tokio::test]
async fn tcp_follow_end_to_end() {
    let bedrock = Arc::new(MockBedrock::new());

    // Pre-publish a backlog of 11 honest records.
    for i in 0..11 {
        bedrock.publish(honest_record((i as i64 % 7) - 3));
    }

    // Bind on an ephemeral port, then run the real follow server.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr: SocketAddr = listener.local_addr().unwrap();
    drop(listener); // free it for run_follow_server
    let server_bedrock = Arc::clone(&bedrock);
    tokio::spawn(async move {
        let _ = run_follow_server(addr, server_bedrock).await;
    });
    tokio::time::sleep(Duration::from_millis(150)).await; // let it bind

    // Connect exactly like the indexer.
    let stream = TcpStream::connect(addr).await.unwrap();
    let mut lines = BufReader::new(stream).lines();

    // Read the 11-record backlog.
    let mut received: Vec<Inscription> = Vec::new();
    for _ in 0..11 {
        let line = tokio::time::timeout(Duration::from_secs(2), lines.next_line())
            .await
            .expect("backlog line within 2s")
            .unwrap()
            .expect("stream open");
        received.push(Inscription::from_line(&line).expect("valid inscription line"));
    }

    // Publish one live record after connecting; it must arrive too.
    bedrock.publish(honest_record(0));
    let line = tokio::time::timeout(Duration::from_secs(2), lines.next_line())
        .await
        .expect("live line within 2s")
        .unwrap()
        .expect("stream open");
    received.push(Inscription::from_line(&line).unwrap());

    // No gaps, no duplicates, strict order.
    for (i, ins) in received.iter().enumerate() {
        assert_eq!(ins.seq, i as u64, "wire stream must preserve dense seq order");
    }

    // And the received set attests (12 honest >= quorum 10).
    let records: Vec<PriceRecord> = received.into_iter().map(|i| i.record).collect();
    let out = run_round(&records, &RoundConfig::default());
    assert_eq!(out.survivors, 12);
    assert!(out.attested_price.is_some());
}
