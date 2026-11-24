use std::time::Duration;

use leansim::node::waggle_pipeline::{Proposer, CHUNKS};
use tokio::time::Instant;

#[test]
fn proposer_waits_for_distinct_complete_committees_and_proving_time() {
    let now = Instant::now();
    let mut proposer = Proposer::new(2, Duration::from_millis(1200));
    proposer.hold(0, now);
    proposer.hold(0, now + Duration::from_millis(10));
    proposer.hold(2, now + Duration::from_millis(20)); // Global proof, not a committee.
    assert_eq!(proposer.due(), None);

    let ready = now + Duration::from_millis(100);
    proposer.hold(1, ready);
    let done = ready + Duration::from_millis(1200);
    assert_eq!(proposer.due(), Some(done));
    assert!(!proposer.finish(done - Duration::from_millis(1)));
    assert!(proposer.finish(done));
    proposer.hold(1, done);
    assert_eq!(proposer.due(), None);
    assert!(!proposer.finish(done));
}

#[test]
fn proofs_travel_in_16_chunks_so_the_root_signature_stays_a_small_share() {
    assert_eq!(CHUNKS, 16);
}
