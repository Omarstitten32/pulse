//! Merkle tree for snapshot integrity.
//!
//! Design:
//!
//! - **Leaf hash**:  `sha256(0x00 || leaf_data)`
//! - **Inner hash**: `sha256(0x01 || left || right)`
//!
//! Domain separation (the 0x00 / 0x01 prefixes) prevents a
//! second-preimage attack where a leaf hash could be reinterpreted
//! as an internal node.
//!
//! - Odd-sized levels are padded with `[0u8; 32]` up to the next
//!   power of two. This keeps the tree perfectly balanced and makes
//!   proof length predictable: `log2(padded_size)`.
//!
//! - An empty tree has root `[0u8; 32]` and zero leaves.

use sha2::{Digest, Sha256};

const LEAF_PREFIX: u8 = 0x00;
const NODE_PREFIX: u8 = 0x01;

fn hash_leaf(data: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([LEAF_PREFIX]);
    h.update(data);
    let mut out = [0u8; 32];
    out.copy_from_slice(&h.finalize());
    out
}

fn hash_node(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([NODE_PREFIX]);
    h.update(left);
    h.update(right);
    let mut out = [0u8; 32];
    out.copy_from_slice(&h.finalize());
    out
}

/// A Merkle tree over a list of 32-byte leaf hashes.
///
/// The input to `from_hashes` is the leaf *value* (typically
/// `sha256(file_contents)`). The tree then hashes those values with
/// the leaf prefix to produce level 0.
pub struct MerkleTree {
    /// levels[0] = hashed leaves, levels[last] = [root]
    levels: Vec<Vec<[u8; 32]>>,
    /// Number of leaves *before* padding.
    original_len: usize,
}

impl MerkleTree {
    /// Build from a list of 32-byte leaf values.
    pub fn from_hashes(mut leaves: Vec<[u8; 32]>) -> Self {
        let original_len = leaves.len();
        if leaves.is_empty() {
            return Self {
                levels: Vec::new(),
                original_len: 0,
            };
        }
        let padded = leaves.len().next_power_of_two();
        while leaves.len() < padded {
            leaves.push([0u8; 32]);
        }
        let level0: Vec<[u8; 32]> = leaves.iter().map(hash_leaf).collect();
        let mut levels = vec![level0];
        while levels.last().unwrap().len() > 1 {
            let prev = levels.last().unwrap();
            let mut next = Vec::with_capacity(prev.len() / 2);
            for pair in prev.chunks_exact(2) {
                next.push(hash_node(&pair[0], &pair[1]));
            }
            levels.push(next);
        }
        Self {
            levels,
            original_len,
        }
    }

    /// The Merkle root. For an empty tree this is `[0u8; 32]`.
    pub fn root(&self) -> [u8; 32] {
        if self.levels.is_empty() {
            return [0u8; 32];
        }
        self.levels.last().unwrap()[0]
    }

    /// Number of leaves (before padding).
    pub fn len(&self) -> usize {
        self.original_len
    }

    /// True when there are zero leaves.
    pub fn is_empty(&self) -> bool {
        self.original_len == 0
    }

    /// Produce a proof for the leaf at `index`.
    /// The proof is a list of sibling hashes from bottom to top.
    /// Verification is possible with `verify_proof`.
    pub fn proof(&self, index: usize) -> Option<Vec<[u8; 32]>> {
        if index >= self.original_len {
            return None;
        }
        let mut proof = Vec::with_capacity(self.levels.len().saturating_sub(1));
        let mut idx = index;
        // Walk all levels except the root level.
        for level in &self.levels[..self.levels.len() - 1] {
            let sibling = idx ^ 1;
            proof.push(level[sibling]);
            idx /= 2;
        }
        Some(proof)
    }

    /// Verify a proof against a root. Returns `true` when the leaf
    /// hashes up to the root along the given proof and index.
    pub fn verify_proof(
        root: &[u8; 32],
        leaf: &[u8; 32],
        index: usize,
        proof: &[[u8; 32]],
    ) -> bool {
        let mut current = hash_leaf(leaf);
        let mut idx = index;
        for sibling in proof {
            if idx & 1 == 0 {
                current = hash_node(&current, sibling);
            } else {
                current = hash_node(sibling, &current);
            }
            idx /= 2;
        }
        current == *root
    }
}
