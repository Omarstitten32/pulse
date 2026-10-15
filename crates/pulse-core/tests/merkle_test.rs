//! Merkle tree tests.
//! All must FAIL before pulse_core::merkle exists.

use pulse_core::merkle::MerkleTree;

fn h(n: u8) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[0] = n;
    out
}

#[test]
fn empty_tree_root_is_zero() {
    let t = MerkleTree::from_hashes(vec![]);
    assert_eq!(t.root(), [0u8; 32]);
    assert_eq!(t.len(), 0);
}

#[test]
fn single_leaf_is_deterministic() {
    let t1 = MerkleTree::from_hashes(vec![h(1)]);
    let t2 = MerkleTree::from_hashes(vec![h(1)]);
    assert_eq!(t1.root(), t2.root());
    assert_eq!(t1.len(), 1);
}

#[test]
fn single_and_double_leaf_differ() {
    let t1 = MerkleTree::from_hashes(vec![h(1)]);
    let t2 = MerkleTree::from_hashes(vec![h(1), h(1)]);
    assert_ne!(t1.root(), t2.root());
}

#[test]
fn order_matters() {
    let t1 = MerkleTree::from_hashes(vec![h(1), h(2), h(3)]);
    let t2 = MerkleTree::from_hashes(vec![h(3), h(2), h(1)]);
    assert_ne!(t1.root(), t2.root());
}

#[test]
fn determinism_100_leaves() {
    let v: Vec<[u8; 32]> = (0..100).map(|i| h(i as u8)).collect();
    let t1 = MerkleTree::from_hashes(v.clone());
    let t2 = MerkleTree::from_hashes(v);
    assert_eq!(t1.root(), t2.root());
    assert_eq!(t1.len(), 100);
}

#[test]
fn proof_verifies_for_each_leaf() {
    let v: Vec<[u8; 32]> = (0..100).map(|i| h(i as u8)).collect();
    let t = MerkleTree::from_hashes(v.clone());
    let root = t.root();
    for (i, leaf) in v.iter().enumerate() {
        let proof = t.proof(i).expect("proof");
        assert!(
            MerkleTree::verify_proof(&root, leaf, i, &proof),
            "leaf {} failed",
            i
        );
    }
}

#[test]
fn proof_fails_for_wrong_leaf() {
    let v: Vec<[u8; 32]> = (0..8).map(|i| h(i as u8)).collect();
    let t = MerkleTree::from_hashes(v);
    let root = t.root();
    let proof = t.proof(3).expect("proof");
    assert!(!MerkleTree::verify_proof(&root, &h(99), 3, &proof));
}

#[test]
fn proof_fails_for_wrong_index() {
    let v: Vec<[u8; 32]> = (0..8).map(|i| h(i as u8)).collect();
    let t = MerkleTree::from_hashes(v.clone());
    let root = t.root();
    let proof = t.proof(3).expect("proof");
    assert!(!MerkleTree::verify_proof(&root, &v[3], 4, &proof));
}

#[test]
fn proof_fails_for_wrong_root() {
    let v: Vec<[u8; 32]> = (0..8).map(|i| h(i as u8)).collect();
    let t = MerkleTree::from_hashes(v.clone());
    let proof = t.proof(3).expect("proof");
    let mut wrong_root = t.root();
    wrong_root[0] ^= 0xff;
    assert!(!MerkleTree::verify_proof(&wrong_root, &v[3], 3, &proof));
}

#[test]
fn tampering_leaf_changes_root() {
    let v1: Vec<[u8; 32]> = (0..100).map(|i| h(i as u8)).collect();
    let mut v2 = v1.clone();
    v2[50] = h(200);
    let t1 = MerkleTree::from_hashes(v1);
    let t2 = MerkleTree::from_hashes(v2);
    assert_ne!(t1.root(), t2.root());
}

#[test]
fn proof_length_is_log2_of_padded_size() {
    // 100 leaves -> padded to 128 -> log2(128) = 7
    let v: Vec<[u8; 32]> = (0..100).map(|i| h(i as u8)).collect();
    let t = MerkleTree::from_hashes(v);
    let proof = t.proof(0).expect("proof");
    assert_eq!(proof.len(), 7);
}
