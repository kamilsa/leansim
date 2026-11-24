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
fn the_merkle_path_of_a_piece_yields_the_root() {
    let key = ProofKey {
        subnet: 2,
        producer: 7,
    };
    let (root, good) = pieces(key, b"a first proof", 4);
    for piece in &good {
        assert_eq!(piece.root(4, 13), Some(root));
    }
    let mut altered = good[1].clone();
    altered.data[0] ^= 1;
    assert!(altered.root(4, 13).is_some_and(|other| other != root));
    let mut outside = good[1].clone();
    outside.index += 4;
    assert_eq!(outside.root(4, 13), None);
    let mut short = good[1].clone();
    short.branch.pop();
    assert_eq!(short.root(4, 13), None);
}

#[test]
fn a_gossiped_piece_is_checked_against_the_root_signature_it_carries() {
    use leansim::network::swarm::node_keypair;
    use leansim::node::subnet_proofs::sign_commitment;
    use leansim::node::subnet_proofs::Admission::{Conflict, Held, Invalid};
    let key = ProofKey {
        subnet: 2,
        producer: 7,
    };
    let producer = node_keypair(7);
    let public = producer.public();
    let (root, good) = pieces(key, b"a first proof", 4);
    let (other_root, other) = pieces(key, b"another proof", 4);
    let signature = sign_commitment(&producer, key, root).unwrap();
    let other_signature = sign_commitment(&producer, key, other_root).unwrap();
    let forged = sign_commitment(&node_keypair(8), key, root).unwrap();
    let mut receiver = Assembly::default();
    // Every gossiped piece must carry the signature: nothing else says the receiver has it.
    assert_eq!(receiver.admit(&public, &[], &good[2], 4, 13), Invalid);
    assert_eq!(receiver.admit(&public, &forged, &good[2], 4, 13), Invalid);
    // No commitment arrived beforehand: the first piece brings it.
    assert_eq!(
        receiver.admit(&public, &signature, &good[2], 4, 13),
        Held { complete: false }
    );
    assert_eq!(receiver.admit(&public, &[], &good[0], 4, 13), Invalid);
    assert_eq!(
        receiver.admit(&public, &other_signature, &good[0], 4, 13),
        Invalid
    );
    // A second root signed by the producer does not replace the first.
    assert_eq!(
        receiver.admit(&public, &other_signature, &other[0], 4, 13),
        Conflict
    );
    for piece in &good[..2] {
        assert_eq!(
            receiver.admit(&public, &signature, piece, 4, 13),
            Held { complete: false }
        );
    }
    assert_eq!(
        receiver.admit(&public, &signature, &good[3], 4, 13),
        Held { complete: true }
    );
    // An invalid piece must not pin a commitment.
    let mut fresh = Assembly::default();
    let mut bad = good[1].clone();
    bad.data[0] ^= 1;
    assert_eq!(fresh.admit(&public, &signature, &bad, 4, 13), Invalid);
    assert_eq!(
        fresh.admit(&public, &other_signature, &other[1], 4, 13),
        Held { complete: false }
    );
}

#[test]
fn a_commitment_is_one_2400_byte_signature_over_the_merkle_root() {
    use leansim::network::swarm::node_keypair;
    use leansim::node::subnet_proofs::{
        sign_commitment, verify_commitment, COMMITMENT_SIGNATURE_BYTES,
    };
    let key = ProofKey {
        subnet: 2,
        producer: 7,
    };
    let (root, _) = pieces(key, b"a first proof", 4);
    let (other_root, _) = pieces(key, b"another proof", 4);
    let signer = node_keypair(7);
    let public = signer.public();
    let signature = sign_commitment(&signer, key, root).unwrap();
    assert_eq!(COMMITMENT_SIGNATURE_BYTES, 2400);
    assert_eq!(signature.len(), 2400);
    assert!(verify_commitment(&public, key, root, &signature));
    assert!(!verify_commitment(&public, key, other_root, &signature));
    let other_key = ProofKey {
        subnet: 3,
        producer: 7,
    };
    assert!(!verify_commitment(&public, other_key, root, &signature));
    assert!(!verify_commitment(
        &node_keypair(8).public(),
        key,
        root,
        &signature
    ));
    // Neither a shorter signature nor altered filler passes.
    assert!(!verify_commitment(&public, key, root, &signature[..64]));
    let mut altered = signature.clone();
    altered[2399] ^= 1;
    assert!(!verify_commitment(&public, key, root, &altered));
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
