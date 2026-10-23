use leansim::metrics::traffic::{Direction, Kind, TrafficMeter};

fn bucket_bytes(
    meter: &mut TrafficMeter,
    at: u64,
) -> Vec<(u64, Vec<(&'static str, u64)>, Vec<(&'static str, u64)>)> {
    meter
        .drain_due(at)
        .iter()
        .map(|bucket| {
            let mut inbound: Vec<(&'static str, u64)> = bucket
                .inbound
                .iter()
                .map(|(kind, bytes)| (kind.as_str(), *bytes))
                .collect();
            let mut outbound: Vec<(&'static str, u64)> = bucket
                .outbound
                .iter()
                .map(|(kind, bytes)| (kind.as_str(), *bytes))
                .collect();
            inbound.sort();
            outbound.sort();
            (bucket.start_ms, inbound, outbound)
        })
        .collect()
}

#[test]
fn a_bucket_flushes_when_the_clock_leaves_it() {
    let mut meter = TrafficMeter::new(100);
    meter.record(10, Direction::In, Kind::Signature, 1_200, "peer:a");
    meter.record(90, Direction::In, Kind::Signature, 1_200, "peer:b");
    assert_eq!(bucket_bytes(&mut meter, 99), vec![]);
    assert_eq!(
        bucket_bytes(&mut meter, 100),
        vec![(0, vec![("signature", 2_400)], vec![])]
    );
    // The bucket is gone: only the open one remains, and it is empty.
    assert_eq!(bucket_bytes(&mut meter, 400), vec![]);
}

#[test]
fn kinds_and_directions_are_kept_apart() {
    let mut meter = TrafficMeter::new(100);
    meter.record(10, Direction::In, Kind::Signature, 100, "peer:a");
    meter.record(20, Direction::Out, Kind::Signature, 300, "node:5");
    meter.record(30, Direction::Out, Kind::ProofPayload, 262_144, "node:9");
    assert_eq!(
        bucket_bytes(&mut meter, 100),
        vec![(
            0,
            vec![("signature", 100)],
            vec![("proof_payload", 262_144), ("signature", 300)]
        )]
    );
}

#[test]
fn per_peer_totals_accumulate_across_buckets() {
    let mut meter = TrafficMeter::new(100);
    meter.record(10, Direction::In, Kind::Signature, 1_200, "peer:a");
    meter.record(250, Direction::In, Kind::Signature, 1_200, "peer:a");
    meter.record(260, Direction::Out, Kind::ProofPayload, 262_144, "node:5");
    let peers = meter.peers();
    assert_eq!(peers["peer:a"].inbound_bytes, 2_400);
    assert_eq!(peers["peer:a"].inbound_msgs, 2);
    assert_eq!(peers["peer:a"].outbound_bytes, 0);
    assert_eq!(peers["node:5"].outbound_bytes, 262_144);
    assert_eq!(peers["node:5"].outbound_msgs, 1);
}

#[test]
fn finish_flushes_the_open_bucket_and_nothing_else() {
    let mut fresh = TrafficMeter::new(100);
    assert!(fresh.finish().is_empty());
    let mut meter = TrafficMeter::new(100);
    meter.record(10, Direction::In, Kind::Signature, 1_200, "peer:a");
    let buckets = meter.finish();
    assert_eq!(buckets.len(), 1);
    assert_eq!(buckets[0].start_ms, 0);
    assert_eq!(buckets[0].inbound[&Kind::Signature], 1_200);
    assert!(meter.finish().is_empty());
}

#[test]
fn a_gap_between_buckets_produces_no_empty_buckets() {
    let mut meter = TrafficMeter::new(100);
    meter.record(10, Direction::In, Kind::Signature, 100, "peer:a");
    assert_eq!(bucket_bytes(&mut meter, 5_000).len(), 1);
    meter.record(5_000, Direction::In, Kind::Signature, 200, "peer:a");
    let buckets = meter.finish();
    assert_eq!(buckets.len(), 1);
    assert_eq!(buckets[0].start_ms, 5_000);
}
