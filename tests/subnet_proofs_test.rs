use leansim::node::subnet_proofs::{pieces, Assembly, ProofKey};

#[test]
fn a_receiver_needs_every_authentic_piece_from_one_producer() {
    let a = ProofKey {
        subnet: 2,
        producer: 7,
    };
    let b = ProofKey {
        subnet: 2,
        producer: 8,
    };
    let (root_a, left) = pieces(a, b"a first proof", 4);
    let (root_b, right) = pieces(b, b"another proof", 4);
    let mut receiver = Assembly::default();
    for piece in &left[..3] {
        assert!(piece.verify(root_a, 4, 13));
        assert!(!receiver.insert(piece, 4));
    }
    assert!(right[3].verify(root_b, 4, 13));
    assert!(!right[3].verify(root_a, 4, 13));
    assert!(!receiver.insert(&right[3], 4));
    let mut invalid = left[3].clone();
    invalid.index += 4;
    assert!(!invalid.verify(root_a, 4, 13));
    invalid = left[3].clone();
    invalid.data[0] ^= 1;
    assert!(!invalid.verify(root_a, 4, 13));
    assert!(receiver.insert(&left[3], 4));
    assert!(!receiver.insert(&left[3], 4));
}

#[test]
fn provider_repair_only_requests_one_copy_then_tries_the_next_provider() {
    use leansim::node::subnet_proofs::Pulls;
    let proof = ProofKey {
        subnet: 0,
        producer: 1,
    };
    let mut pulls = Pulls::default();
    assert_eq!(pulls.announce(proof, 2), Some(2));
    assert_eq!(pulls.announce(proof, 3), None);
    assert_eq!(pulls.failed(proof, 2), Some(3));
    assert!(pulls.finish(proof));
    assert_eq!(pulls.announce(proof, 4), None);
    assert_eq!(pulls.failed(proof, 3), None);
    assert!(!pulls.finish(proof));
}
