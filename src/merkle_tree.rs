//! For now the functionality we require out of merkle trees is quite simple, so it does not
//! make sense to include an additional dependency, such as
//! [`merkletree`](https://docs.rs/merkletree/0.21.0/merkletree/).
//!
//! # Example
//! ```
//! # use rand_core::{OsRng, RngCore};
//! # use atms::MerkleTree;
//! # use blake2::Blake2b;
//! # fn main() {
//! let mut rng = OsRng::default();
//! let mut keys = Vec::with_capacity(32);
//! for _ in 0..32 {
//!     let mut leaf = [0u8; 32];
//!     rng.fill_bytes(&mut leaf);
//!     keys.push(leaf.to_vec());
//! }
//! let mt = MerkleTree::<Blake2b>::create(&keys);
//! let path = mt.get_path(3);
//! assert!(mt.to_commitment().check(&keys[3], &path).is_ok());
//!
//! # }
use crate::error::MerkleTreeError;
use std::fmt::Debug;
use std::marker::PhantomData;
use blake2::Blake2b;
use digest::{Digest, FixedOutput, Update};
use serde::{Serialize, Deserialize};

/// Path of hashes from root to leaf in a Merkle Tree. Contains all hashes on the path, and the index
/// of the leaf.
/// Used to verify the credentials of users and signatures.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Path<D: Digest + FixedOutput> {
    values: Vec<Vec<u8>>,
    index: usize,
    hasher: PhantomData<D>,
}

impl<D: Digest + FixedOutput> Path<D> {
    /// Convert the `Path` into byte representation.
    // todo: if we want to further reduce the path size, we can use smaller ints for length and index
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut result = Vec::new();
        let len = self.values.len();
        result.extend_from_slice(&len.to_be_bytes());
        result.extend_from_slice(&self.index.to_be_bytes());

        for node in &self.values {
            result.extend_from_slice(node.as_slice());
        }
        result
    }

    // /// Try to convert a byte string into a `Path`.
    // pub fn from_bytes(bytes: &[u8]) -> Result<Self, MerkleTreeError> {
    //     let mut size_bytes = [0u8; 8];
    //     size_bytes.copy_from_slice(&bytes[..8]);
    //     let size = u64::from_be_bytes(size_bytes);
    //     let mut index_bytes = [0u8; 8];
    //     index_bytes.copy_from_slice(&bytes[8..16]);
    //     let index = u64::from_be_bytes(index_bytes);
    //     let node_size = D::output_size() as u64;
    //
    //     let mut vec_nodes = Vec::new();
    //     for slice in bytes[16..(16 + node_size * size)].chunks(node_size) {
    //         vec_nodes.push(slice.to_vec());
    //     }
    //
    //     // todo: This is platform dependend, and will fail. Resolve
    //     Ok(Self{ values: vec_nodes, index: index as usize, hasher: Default::default() })
    // }
}

/// Tree of hashes, providing a commitment of data and its ordering.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MerkleTreeCommitment<D: Digest>
{
    /// Root of the merkle tree, representing the commitment of all its leaves.
    pub value: Vec<u8>,
    /// Phantom type to link commitment to its hasher
    hasher: PhantomData<D>
}

impl<D: Digest + FixedOutput> MerkleTreeCommitment<D>
{
    /// Check an inclusion proof that `val` is part of the tree.
    pub fn check(&self, val: &[u8], proof: &Path<D>) -> Result<(), MerkleTreeError> {
        let mut idx = proof.index;

        let mut h = vec![0u8; D::output_size()];
        h[..val.len()].copy_from_slice(val);
        for p in &proof.values {
            if (idx & 0b1) == 0 {
                h = D::new()
                    .chain(h)
                    .chain(p)
                    .finalize()
                    .to_vec();
            } else {
                h = D::new()
                    .chain(p)
                    .chain(h)
                    .finalize()
                    .to_vec();
            }
            idx >>= 1;
        }

        if h == self.value {
            return Ok(());
        }
        Err(MerkleTreeError::InvalidPath)
    }
}

/// Tree of hashes, providing a commitment of data and its ordering.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MerkleTree<D: Digest + FixedOutput>
{
    /// The nodes are stored in an array heap:
    /// nodes[0] is the root,
    /// the parent of nodes[i] is nodes[(i-1)/2]
    /// the children of nodes[i] are {nodes[2i + 1], nodes[2i + 2]}
    /// All nodes have size Output<D>::output_size(), even leafs (which are padded with
    /// zeroes).
    nodes: Vec<Vec<u8>>,

    /// The leaves begin at nodes[leaf_off]
    leaf_off: usize,

    /// Number of leaves cached here
    n: usize,
    /// Phantom type to link the tree with its hasher
    hasher: PhantomData<D>
}

impl<D: Digest + FixedOutput> MerkleTree<D>
{
    /// Provide a non-empty list of leaves, `create` generate its corresponding `MerkleTree`.
    pub fn create(leaves: &[Vec<u8>]) -> MerkleTree<D> {
        let n = leaves.len();
        assert!(n > 0, "MerkleTree::create() called with no leaves");

        let num_nodes = n + n.next_power_of_two() - 1;

        let mut nodes = vec![vec![0u8; D::output_size()]; num_nodes];

        for i in 0..n {
            nodes[num_nodes - n + i][..leaves[i].len()].copy_from_slice(&leaves[i]);
        }

        for i in (0..num_nodes - n).rev() {
            let z = vec![0u8; D::output_size()];
            let left = if left_child(i) < num_nodes {
                nodes[left_child(i)].clone()
            } else {
                z
            };
            let right = if right_child(i) < num_nodes {
                nodes[right_child(i)].clone()
            } else {
                left.clone()
            };
            nodes[i] = D::new()
                .chain(left)
                .chain(right)
                .finalize()
                .to_vec();
        }

        Self {
            nodes,
            n,
            leaf_off: num_nodes - n,
            hasher: PhantomData::default()
        }
    }

    /// Convert merkle tree to a commitment. This function simply returns the root
    pub fn to_commitment(&self) -> MerkleTreeCommitment<D> {
        MerkleTreeCommitment {
            value: self.nodes[0].clone(),
            hasher: self.hasher
        }
    }

    /// Get the root of the tree
    pub fn root(&self) -> Vec<u8> {
        self.nodes[0].clone()
    }

    /// Get a path (hashes of siblings of the path to the root node
    /// for the `i`th value stored in the tree.
    /// Requires `i < self.n`
    pub fn get_path(&self, i: usize) -> Path<D> {
        assert!(
            i < self.n,
            "Proof index out of bounds: asked for {} out of {}",
            i,
            self.n
        );
        let mut idx = self.idx_of_leaf(i);
        let mut proof = Vec::new();

        while idx > 0 {
            let h = if sibling(idx) < self.nodes.len() {
                self.nodes[sibling(idx)].clone()
            } else {
                self.nodes[idx].clone()
            };
            proof.push(h.clone());
            idx = parent(idx);
        }

        Path{
            values: proof,
            index: i,
            hasher: Default::default()
        }
    }

    fn idx_of_leaf(&self, i: usize) -> usize {
        self.leaf_off + i
    }
}

//////////////////
// Heap Helpers //
//////////////////

fn parent(i: usize) -> usize {
    assert!(i > 0, "The root node does not have a parent");
    (i - 1) / 2
}

fn left_child(i: usize) -> usize {
    (2 * i) + 1
}

fn right_child(i: usize) -> usize {
    (2 * i) + 2
}

fn sibling(i: usize) -> usize {
    assert!(i > 0, "The root node does not have a sibling");
    // In the heap representation, the left sibling is always odd
    // And the right sibling is the next node
    // We're assuming that the heap is complete
    if i % 2 == 1 {
        i + 1
    } else {
        i - 1
    }
}

/////////////////////
// Testing         //
/////////////////////

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::collection::{hash_set, vec};
    use proptest::prelude::*;

    prop_compose! {
        fn arb_tree(max_size: u32)
                   (v in vec(vec(any::<u8>(), 2..16), 2..(max_size as usize))) -> (MerkleTree<blake2::Blake2b>, Vec<Vec<u8>>) {
             (MerkleTree::<blake2::Blake2b>::create(&v), v)
        }
    }

    proptest! {
        // Test the relation that t.get_path(i) is a valid
        // proof for i
        #![proptest_config(ProptestConfig::with_cases(100))]
        #[test]
        fn test_create_proof((t, values) in arb_tree(30)) {
            values.iter().enumerate().for_each(|(i, _v)| {
                let pf = t.get_path(i);
                assert!(t.to_commitment().check(&values[i], &pf).is_ok());
            })
        }

        #[test]
        fn test_serde((t, values) in arb_tree(30)) {
            values.iter().enumerate().for_each(|(i, _v)| {
                let pf = t.get_path(i);
                assert!(t.to_commitment().check(&values[i], &pf).is_ok());
                let mut writer = Vec::new();
                ciborium::ser::into_writer(&pf, &mut writer).unwrap();
                let test: Path<Blake2b> = ciborium::de::from_reader(writer.as_slice()).unwrap();

                assert!(t.to_commitment().check(&values[i], &test).is_ok());
            })
        }
    }

    fn pow2_plus1(h: usize) -> usize {
        1 + 2_usize.pow(h as u32)
    }

    prop_compose! {
        // Returns values with a randomly generated path
        fn values_with_invalid_proof(max_height: usize)
                                    (h in 1..max_height)
                                    (vals in hash_set(vec(any::<u8>(), 2..16), pow2_plus1(h)),
                                     proof in vec(vec(any::<u8>(), 16), h)) -> (Vec<Vec<u8>>, Vec<Vec<u8>>) {
            (vals.into_iter().collect(), proof)
        }
    }

    proptest! {
        #[test]
        fn test_create_invalid_proof(
            i in any::<usize>(),
            (values, proof) in values_with_invalid_proof(10)
        ) {
            let t = MerkleTree::<blake2::Blake2b>::create(&values[1..]);
            let idx = i % (values.len() - 1);
            let path = Path{values: proof, index: idx, hasher: PhantomData::<Blake2b>::default()};
            assert!(t.to_commitment().check(&values[0], &path).is_err());
        }

        #[test]
        fn test_mt_serde(
            i in any::<usize>(),
            (values, proof) in values_with_invalid_proof(10)
        ) {
            let t = MerkleTree::<Blake2b>::create(&values[1..]);
            let idx = i % (values.len() - 1);
            let path = Path{values: proof, index: idx, hasher: PhantomData::<Blake2b>::default()};
            assert!(t.to_commitment().check(&values[0], &path).is_err());
            let mut writer = Vec::new();
            ciborium::ser::into_writer(&t, &mut writer).unwrap();
            let test: MerkleTree<Blake2b> = ciborium::de::from_reader(writer.as_slice()).unwrap();
            assert!(test.to_commitment().check(&values[0], &path).is_err());
        }

        #[test]
        fn test_mc_serde(
            i in any::<usize>(),
            (values, proof) in values_with_invalid_proof(10)
        ) {
            let t = MerkleTree::<Blake2b>::create(&values[1..]).to_commitment();
            let idx = i % (values.len() - 1);
            let path = Path{values: proof, index: idx, hasher: PhantomData::<Blake2b>::default()};
            assert!(t.check(&values[0], &path).is_err());
            let mut writer = Vec::new();
            ciborium::ser::into_writer(&t, &mut writer).unwrap();
            let test: MerkleTreeCommitment<Blake2b> = ciborium::de::from_reader(writer.as_slice()).unwrap();
            assert!(test.check(&values[0], &path).is_err());
        }
    }
}
