//! Code sourced from:
//! https://github.com/sigp/lighthouse/blob/bf533c8e42/consensus/merkle_proof/src/lib.rs
//! Vendored via trin commit `30aeef8`.

use alloy::primitives::B256;
use ethereum_hashing::{hash, hash32_concat, ZERO_HASHES};
use lazy_static::lazy_static;

use crate::merkle::safe_arith::ArithError;

const MAX_TREE_DEPTH: usize = 32;
const EMPTY_SLICE: &[B256] = &[];

lazy_static! {
    /// Zero nodes to act as "synthetic" left and right subtrees of other zero nodes.
    static ref ZERO_NODES: Vec<MerkleTree> = {
        (0..=MAX_TREE_DEPTH).map(MerkleTree::Zero).collect()
    };
}

/// Right-sparse Merkle tree.
#[derive(Debug, PartialEq)]
pub enum MerkleTree {
    Finalized(B256),
    Leaf(B256),
    Node(B256, Box<Self>, Box<Self>),
    Zero(usize),
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum MerkleTreeError {
    LeafReached,
    MerkleTreeFull,
    Invalid,
    DepthTooSmall,
    ArithError,
    ZeroNodeFinalized,
    FinalizedNodePushed,
    InvalidSnapshot(InvalidSnapshot),
    ProofEncounteredFinalizedNode,
    PleaseNotifyTheDevs,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum InvalidSnapshot {
    EmptyBranchWithNonZeroDeposits(usize),
    EndOfTree,
}

impl MerkleTree {
    pub fn create(leaves: &[B256], depth: usize) -> Self {
        use MerkleTree::*;

        if leaves.is_empty() {
            return Zero(depth);
        }

        match depth {
            0 => {
                debug_assert_eq!(leaves.len(), 1);
                Leaf(leaves[0])
            }
            _ => {
                let subtree_capacity = 2usize.pow(depth as u32 - 1);
                let (left_leaves, right_leaves) = if leaves.len() <= subtree_capacity {
                    (leaves, EMPTY_SLICE)
                } else {
                    leaves.split_at(subtree_capacity)
                };

                let left_subtree = MerkleTree::create(left_leaves, depth - 1);
                let right_subtree = MerkleTree::create(right_leaves, depth - 1);
                let hash = B256::from_slice(&hash32_concat(
                    left_subtree.hash().as_slice(),
                    right_subtree.hash().as_slice(),
                ));

                Node(hash, Box::new(left_subtree), Box::new(right_subtree))
            }
        }
    }

    pub fn hash(&self) -> B256 {
        match *self {
            MerkleTree::Finalized(h) => h,
            MerkleTree::Leaf(h) => h,
            MerkleTree::Node(h, _, _) => h,
            MerkleTree::Zero(depth) => B256::from_slice(&ZERO_HASHES[depth]),
        }
    }

    pub fn left_and_right_branches(&self) -> Option<(&Self, &Self)> {
        match *self {
            MerkleTree::Finalized(_) | MerkleTree::Leaf(_) | MerkleTree::Zero(0) => None,
            MerkleTree::Node(_, ref l, ref r) => Some((l, r)),
            MerkleTree::Zero(depth) => Some((&ZERO_NODES[depth - 1], &ZERO_NODES[depth - 1])),
        }
    }

    pub fn is_leaf(&self) -> bool {
        matches!(self, MerkleTree::Leaf(_))
    }

    pub fn generate_proof(
        &self,
        index: usize,
        depth: usize,
    ) -> Result<(B256, Vec<B256>), MerkleTreeError> {
        let mut proof = vec![];
        let mut current_node = self;
        let mut current_depth = depth;
        while current_depth > 0 {
            let ith_bit = (index >> (current_depth - 1)) & 0x01;
            if let &MerkleTree::Finalized(_) = current_node {
                return Err(MerkleTreeError::ProofEncounteredFinalizedNode);
            }
            #[allow(clippy::unwrap_used)]
            let (left, right) = current_node.left_and_right_branches().unwrap();

            if ith_bit == 1 {
                proof.push(left.hash());
                current_node = right;
            } else {
                proof.push(right.hash());
                current_node = left;
            }
            current_depth -= 1;
        }

        debug_assert_eq!(proof.len(), depth);
        debug_assert!(current_node.is_leaf());

        proof.reverse();

        Ok((current_node.hash(), proof))
    }
}

/// Verify a proof that `leaf` exists at `index` in a Merkle tree rooted at `root`.
pub fn verify_merkle_proof(
    leaf: B256,
    branch: &[B256],
    depth: usize,
    index: usize,
    root: B256,
) -> bool {
    if branch.len() == depth {
        merkle_root_from_branch(leaf, branch, depth, index) == root
    } else {
        false
    }
}

/// Compute a root hash from a leaf and a Merkle proof.
pub fn merkle_root_from_branch(leaf: B256, branch: &[B256], depth: usize, index: usize) -> B256 {
    assert_eq!(branch.len(), depth, "proof length should equal depth");

    let mut merkle_root = leaf.as_slice().to_vec();

    for (i, leaf) in branch.iter().enumerate().take(depth) {
        let ith_bit = (index >> i) & 0x01;
        if ith_bit == 1 {
            merkle_root = hash32_concat(leaf.as_slice(), &merkle_root)[..].to_vec();
        } else {
            let mut input = merkle_root;
            input.extend_from_slice(leaf.as_slice());
            merkle_root = hash(&input);
        }
    }

    B256::from_slice(&merkle_root)
}

impl From<ArithError> for MerkleTreeError {
    fn from(_: ArithError) -> Self {
        MerkleTreeError::ArithError
    }
}

impl From<InvalidSnapshot> for MerkleTreeError {
    fn from(e: InvalidSnapshot) -> Self {
        MerkleTreeError::InvalidSnapshot(e)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_small_example() {
        let leaf_b00 = B256::from([0xAA; 32]);
        let leaf_b01 = B256::from([0xBB; 32]);
        let leaf_b10 = B256::from([0xCC; 32]);
        let leaf_b11 = B256::from([0xDD; 32]);

        let node_b0x = B256::from_slice(&hash32_concat(leaf_b00.as_slice(), leaf_b01.as_slice()));
        let node_b1x = B256::from_slice(&hash32_concat(leaf_b10.as_slice(), leaf_b11.as_slice()));

        let root = B256::from_slice(&hash32_concat(node_b0x.as_slice(), node_b1x.as_slice()));

        let tree = MerkleTree::create(&[leaf_b00, leaf_b01, leaf_b10, leaf_b11], 2);
        assert_eq!(tree.hash(), root);
    }

    #[test]
    fn verify_small_example() {
        let leaf_b00 = B256::from([0xAA; 32]);
        let leaf_b01 = B256::from([0xBB; 32]);
        let leaf_b10 = B256::from([0xCC; 32]);
        let leaf_b11 = B256::from([0xDD; 32]);

        let node_b0x = B256::from_slice(&hash32_concat(leaf_b00.as_slice(), leaf_b01.as_slice()));
        let node_b1x = B256::from_slice(&hash32_concat(leaf_b10.as_slice(), leaf_b11.as_slice()));

        let root = B256::from_slice(&hash32_concat(node_b0x.as_slice(), node_b1x.as_slice()));

        assert!(verify_merkle_proof(
            leaf_b00,
            &[leaf_b01, node_b1x],
            2,
            0b00,
            root
        ));
        assert!(verify_merkle_proof(
            leaf_b01,
            &[leaf_b00, node_b1x],
            2,
            0b01,
            root
        ));
        assert!(verify_merkle_proof(
            leaf_b10,
            &[leaf_b11, node_b0x],
            2,
            0b10,
            root
        ));
        assert!(verify_merkle_proof(
            leaf_b11,
            &[leaf_b10, node_b0x],
            2,
            0b11,
            root
        ));

        // Negative cases
        assert!(!verify_merkle_proof(leaf_b01, &[], 2, 0b01, root));
        assert!(!verify_merkle_proof(
            leaf_b01,
            &[node_b1x, leaf_b00],
            2,
            0b01,
            root
        ));
        assert!(!verify_merkle_proof(leaf_b01, &[leaf_b00], 2, 0b01, root));
        assert!(!verify_merkle_proof(
            leaf_b01,
            &[leaf_b00, node_b1x],
            2,
            0b10,
            root
        ));
        assert!(!verify_merkle_proof(
            leaf_b01,
            &[leaf_b00, node_b1x],
            2,
            0b01,
            node_b1x
        ));
    }

    #[test]
    fn verify_zero_depth() {
        let leaf = B256::from([0xD6; 32]);
        let junk = B256::from([0xD7; 32]);
        assert!(verify_merkle_proof(leaf, &[], 0, 0, leaf));
        assert!(!verify_merkle_proof(leaf, &[], 0, 7, junk));
    }
}
