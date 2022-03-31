//! Merkle tree module, exposing several ops on Merkle Trees.
use crate::error::MerkleTreeError;
use digest::{Digest, FixedOutput};
use std::convert::TryFrom;
use std::fmt::Debug;
use std::marker::PhantomData;

/// Path of hashes from root to leaf in a Merkle Tree. Contains all hashes on the path, and the index
/// of the leaf.
/// Used to verify the credentials of users and signatures.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Path<D: Digest + FixedOutput> {
    pub(crate) values: Vec<Vec<u8>>,
    index: usize,
    hasher: PhantomData<D>,
}

/// Path for a batch of indices. The size of a batched path, $s$, depends
/// on how the nodes are distributed among the leaves. It has size
/// $h − \log 2 k \leq s \leq k(h − \log 2 k)$, with $h$
/// the height of the tree and $k$ the size of the batch. This is considerably better than the
/// trivial $k \cdot h$ solution of appending $k$ paths.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BatchPath<D: Digest + FixedOutput> {
    pub(crate) values: Vec<Vec<u8>>,
    indices: Vec<usize>,
    hasher: PhantomData<D>,
}

impl<D: Digest + FixedOutput> Path<D> {
    /// Convert the `Path` into byte representation. The size of a path is
    /// $8 + 8 + n * S$ where $n$ is the number of hashes in the path and
    /// $S$ the output size of the digest function.
    ///
    /// # Layout
    /// The layour of a `Path` is
    /// * Length of path
    /// * Index of element
    /// * $n$ hash outputs
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut result = Vec::with_capacity(4 + 4 + self.values.len() * D::output_size());
        let len = u32::try_from(self.values.len()).expect("Length must fit in u32");
        result.extend_from_slice(&len.to_be_bytes());
        result.extend_from_slice(
            &u32::try_from(self.index)
                .expect("Index must fit in u32")
                .to_be_bytes(),
        );

        for node in &self.values {
            result.extend_from_slice(node.as_slice());
        }
        result
    }

    /// Try to convert a byte string into a `Path`.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, MerkleTreeError> {
        let mut u32_bytes = [0u8; 4];
        u32_bytes.copy_from_slice(&bytes[..4]);
        let size = usize::try_from(u32::from_be_bytes(u32_bytes))
            .expect("Library should be built in 32 bit targets or higher");
        u32_bytes.copy_from_slice(&bytes[4..8]);
        let index = usize::try_from(u32::from_be_bytes(u32_bytes))
            .expect("Library should be built in 32 bit targets or higher");
        let node_size = D::output_size();

        let mut vec_nodes = Vec::with_capacity(size);
        for slice in bytes[8..8 + node_size * size].chunks(node_size) {
            vec_nodes.push(slice.to_vec());
        }

        Ok(Self {
            values: vec_nodes,
            index,
            hasher: Default::default(),
        })
    }
}

impl<D: Digest + FixedOutput> BatchPath<D> {
    /// Convert the `BatchPath` into byte representation.
    ///
    /// # Layout
    /// The layout of a `Path` is
    /// * Length of proof, $n$
    /// * Length of batch
    /// * Indices of element
    /// * $n$ hash outputs
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut result = Vec::with_capacity(
            4 + 4 + self.indices.len() * 4 + self.values.len() * D::output_size(),
        ); // 4 values.len() + 4 size_batch + size_batch * 4 all indices + len * Digest::output_size() all values
        let len = u32::try_from(self.values.len()).expect("Length must fit in u32");
        let size_batch = u32::try_from(self.indices.len()).expect("Length must fit in u32");
        result.extend_from_slice(&len.to_be_bytes());
        result.extend_from_slice(&size_batch.to_be_bytes());

        for &index in &self.indices {
            result.extend_from_slice(
                &u32::try_from(index)
                    .expect("Length must fit in u32")
                    .to_be_bytes(),
            );
        }

        for node in &self.values {
            result.extend_from_slice(node.as_slice());
        }
        result
    }

    /// Try to convert a byte string into a `BatchPath`.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, MerkleTreeError> {
        let mut u32_bytes = [0u8; 4];
        u32_bytes.copy_from_slice(&bytes[..4]);
        let len = usize::try_from(u32::from_be_bytes(u32_bytes))
            .expect("Library should be built in 32 bit targets or higher");
        u32_bytes.copy_from_slice(&bytes[4..8]);
        let size_batch = usize::try_from(u32::from_be_bytes(u32_bytes))
            .expect("Library should be built in 32 bit targets or higher");
        let mut indices = Vec::with_capacity(size_batch);

        for slice in bytes[8..8 + 4 * size_batch].chunks(4) {
            u32_bytes.copy_from_slice(slice);
            indices.push(
                usize::try_from(u32::from_be_bytes(u32_bytes))
                    .expect("Library should be built in 32 bit targets or higher"),
            );
        }

        let node_size = D::output_size();
        let mut vec_nodes = Vec::with_capacity(len);
        for slice in bytes[8 + 4 * size_batch..].chunks(node_size) {
            vec_nodes.push(slice.to_vec());
        }

        Ok(Self {
            values: vec_nodes,
            indices,
            hasher: Default::default(),
        })
    }
}

/// Tree of hashes, providing a commitment of data and its ordering.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MerkleTreeCommitment<D: Digest> {
    /// Root of the merkle tree, representing the commitment of all its leaves.
    pub value: Vec<u8>,
    /// Number of committed leaves.
    pub nr_leaves: usize,
    /// Phantom type to link commitment to its hasher.
    hasher: PhantomData<D>,
}

impl<D: Digest + FixedOutput> MerkleTreeCommitment<D> {
    /// Check an inclusion proof that `val` is part of the tree by traveling the whole path
    /// until the root.
    ///
    /// # Error
    /// Returns an error if the path is invalid.
    ///
    /// # Example
    /// ```
    /// # use rand_core::{OsRng, RngCore};
    /// # use atms::MerkleTree;
    /// # use blake2::Blake2b;
    /// # fn main() {
    /// let mut rng = OsRng::default();
    /// // We generate the keys.
    /// let mut keys = Vec::with_capacity(32);
    /// for _ in 0..32 {
    ///     let mut leaf = [0u8; 32];
    ///     rng.fill_bytes(&mut leaf);
    ///     keys.push(leaf.to_vec());
    /// }
    /// // Compute the Merkle tree of the keys.
    /// let mt = MerkleTree::<Blake2b>::create(&keys);
    /// // Compute the path of key in position 3.
    /// let path = mt.get_path(3);
    /// // Verify the proof of membership with respect to the merkle commitment.
    /// assert!(mt.to_commitment().check(&keys[3], &path).is_ok());
    ///
    /// # }
    pub fn check(&self, val: &[u8], proof: &Path<D>) -> Result<(), MerkleTreeError> {
        let mut idx = proof.index;

        let mut h = D::digest(val).to_vec();
        for p in &proof.values {
            if (idx & 0b1) == 0 {
                h = D::new().chain(h).chain(p).finalize().to_vec();
            } else {
                h = D::new().chain(p).chain(h).finalize().to_vec();
            }
            idx >>= 1;
        }

        if h == self.value {
            return Ok(());
        }
        Err(MerkleTreeError::InvalidPath)
    }

    /// Check a proof of a batched opening
    ///
    /// # Error
    /// Returns an error if the proof is invalid.
    ///
    /// # Example
    /// ```
    /// # use rand_core::{OsRng, RngCore};
    /// # use atms::MerkleTree;
    /// # use blake2::Blake2b;
    /// # fn main() {
    /// let mut rng = OsRng::default();
    /// // We generate the keys.
    /// let mut keys = Vec::with_capacity(32);
    /// for _ in 0..32 {
    ///     let mut leaf = [0u8; 32];
    ///     rng.fill_bytes(&mut leaf);
    ///     keys.push(leaf.to_vec());
    /// }
    /// // Compute the Merkle tree of the keys.
    /// let mt = MerkleTree::<Blake2b>::create(&keys);
    /// // Compute the path of keys in position [1, 3, 7, 11].
    /// let indices = vec![1, 3, 7, 11];
    /// let values = indices.iter().map(|i| keys[*i].clone()).collect::<Vec<_>>();
    /// let path = mt.get_batched_path(indices);
    /// // Verify the proof of membership with respect to the merkle commitment.
    /// assert!(mt.to_commitment().check_batched(&values, &path).is_ok());
    ///
    /// # }
    pub fn check_batched(
        &self,
        batch_val: &[Vec<u8>],
        proof: &BatchPath<D>,
    ) -> Result<(), MerkleTreeError> {
        if batch_val.len() != proof.indices.len() {
            return Err(MerkleTreeError::InvalidPath);
        }
        let mut ordered_indices: Vec<usize> = proof.indices.clone();
        ordered_indices.sort_unstable();

        if ordered_indices != proof.indices {
            return Err(MerkleTreeError::InvalidPath);
        }

        let nr_nodes = self.nr_leaves + self.nr_leaves.next_power_of_two() - 1;

        ordered_indices = ordered_indices
            .into_iter()
            .map(|i| i + self.nr_leaves.next_power_of_two() - 1)
            .collect();

        let mut idx = ordered_indices[0];
        // First we need to hash the leave values
        let mut leaves: Vec<Vec<u8>> = batch_val
            .iter()
            .map(|val| D::digest(val).to_vec())
            .collect();

        let mut values = proof.values.clone();

        while idx > 0 {
            let mut new_hashes = Vec::with_capacity(ordered_indices.len());
            let mut new_indices = Vec::with_capacity(ordered_indices.len());
            let mut i = 0;
            idx = parent(idx);
            while i < ordered_indices.len() {
                new_indices.push(parent(ordered_indices[i]));
                if ordered_indices[i] & 1 == 0 {
                    new_hashes.push(
                        D::new()
                            .chain(&values.get(0).ok_or(MerkleTreeError::InvalidPath)?)
                            .chain(&leaves[i])
                            .finalize()
                            .to_vec(),
                    );

                    values.remove(0);
                } else {
                    let sibling = sibling(ordered_indices[i]);
                    if i < ordered_indices.len() - 1 && ordered_indices[i + 1] == sibling {
                        new_hashes.push(
                            D::new()
                                .chain(&leaves[i])
                                .chain(&leaves[i + 1])
                                .finalize()
                                .to_vec(),
                        );
                        i += 1;
                    } else if sibling < nr_nodes {
                        new_hashes.push(
                            D::new()
                                .chain(&leaves[i])
                                .chain(&values.get(0).ok_or(MerkleTreeError::InvalidPath)?)
                                .finalize()
                                .to_vec(),
                        );
                        values.remove(0);
                    } else {
                        new_hashes.push(
                            D::new()
                                .chain(&leaves[i])
                                .chain(&D::digest(&[0u8]))
                                .finalize()
                                .to_vec(),
                        );
                    }
                }
                i += 1;
            }
            leaves = new_hashes.clone();
            ordered_indices = new_indices.clone();
        }

        if leaves.len() == 1 && leaves[0] == self.value {
            return Ok(());
        }

        Err(MerkleTreeError::InvalidPath)
    }

    /// Convert a `MerkleTreeCommitment` to a byte array of $S + 8$ bytes, where $S$ is the output
    /// size of the hash function.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut result = Vec::with_capacity(D::output_size() + 8);
        result.extend_from_slice(
            &u32::try_from(self.nr_leaves)
                .expect("Index must fit in u32")
                .to_be_bytes(),
        );
        result.extend_from_slice(&self.value);
        result
    }

    /// Convert a byte array into a `MerkleTreeCommitment`.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, MerkleTreeError> {
        let mut usize_bytes = [0u8; 4];
        usize_bytes.copy_from_slice(&bytes[..4]);
        let nr_leaves = usize::try_from(u32::from_be_bytes(usize_bytes))
            .expect("Library should be built in 32 bit targets or higher");
        if bytes[4..].len() == D::output_size() {
            return Ok(Self {
                value: bytes[4..].to_vec(),
                nr_leaves,
                hasher: PhantomData::default(),
            });
        }
        Err(MerkleTreeError::InvalidSizedBytes)
    }
}

/// Tree of hashes, providing a commitment of data and its ordering.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MerkleTree<D: Digest + FixedOutput> {
    /// The nodes are stored in an array heap:
    /// `nodes[0]` is the root,
    /// the parent of `nodes[i]` is `nodes[(i-1)/2]`
    /// the children of `nodes[i]` are `{nodes[2i + 1], nodes[2i + 2]}`
    /// All nodes have size `Output<D>::output_size()`, even leafs (which are padded with
    /// zeroes).
    pub(crate) nodes: Vec<Vec<u8>>,
    /// The leaves begin at `nodes[leaf_off]`
    leaf_off: usize,
    /// Number of leaves cached here
    pub(crate) n: usize,
    /// Phantom type to link the tree with its hasher
    hasher: PhantomData<D>,
}

impl<D: Digest + FixedOutput> MerkleTree<D> {
    /// Provide a non-empty list of leaves, `create` generate its corresponding `MerkleTree`.
    pub fn create(leaves: &[Vec<u8>]) -> MerkleTree<D> {
        let n = leaves.len();
        assert!(n > 0, "MerkleTree::create() called with no leaves");

        let num_nodes = n + n.next_power_of_two() - 1;

        let mut nodes = vec![vec![0u8]; num_nodes];

        for i in 0..leaves.len() {
            nodes[num_nodes - n + i] = D::digest(&leaves[i].clone()).to_vec();
        }

        for i in (0..num_nodes - n).rev() {
            let z = D::digest(&[0u8]).to_vec();
            let left = if left_child(i) < num_nodes {
                &nodes[left_child(i)]
            } else {
                &z
            };
            let right = if right_child(i) < num_nodes {
                &nodes[right_child(i)]
            } else {
                &z
            };
            nodes[i] = D::new().chain(left).chain(right).finalize().to_vec();
        }

        Self {
            nodes,
            n,
            leaf_off: num_nodes - n,
            hasher: PhantomData::default(),
        }
    }

    /// Convert merkle tree to a commitment. This function simply returns the root
    pub fn to_commitment(&self) -> MerkleTreeCommitment<D> {
        MerkleTreeCommitment {
            value: self.nodes[0].clone(),
            nr_leaves: self.n,
            hasher: self.hasher,
        }
    }

    /// Get the root of the tree.
    pub fn root(&self) -> Vec<u8> {
        self.nodes[0].clone()
    }

    /// Get a path (hashes of siblings of the path to the root node)
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
                D::digest(&[0u8]).to_vec()
            };
            proof.push(h.clone());
            idx = parent(idx);
        }

        Path {
            values: proof,
            index: i,
            hasher: Default::default(),
        }
    }

    /// Get a path for a batch of leaves. We use the Octopus algorithm to avoid redundancy
    /// with nodes in the path. First, the leaf indices are sorted. Then, for each level of
    /// the Merkle tree, in a bottom-up order, for each index we add its parent to the list of
    /// indices at the upper level. We then compute the index of its sibling. If the next
    /// index to authenticate happens to be the sibling, then we skip the sibling.
    /// Otherwise, we add the sibling to the list of authentication nodes.
    ///
    /// # Panics
    /// If the indices provided are out of bounds (higher than the number of elements
    /// committed in the `MerkleTree`) or are not ordered, the function fails.
    pub fn get_batched_path(&self, indices: Vec<usize>) -> BatchPath<D> {
        assert!(
            !indices.is_empty(),
            "get_batched_path() called with no indices"
        );
        for i in &indices {
            assert!(
                i < &self.n,
                "Proof index out of bounds: asked for {} out of {}",
                i,
                self.n
            );
        }

        let mut ordered_indices: Vec<usize> = indices.clone();
        ordered_indices.sort_unstable();

        assert_eq!(ordered_indices, indices, "Indices should be ordered");

        ordered_indices = ordered_indices
            .into_iter()
            .map(|i| self.idx_of_leaf(i))
            .collect();

        let mut idx = ordered_indices[0];
        let mut proof = Vec::new();

        while idx > 0 {
            let mut new_indices = Vec::with_capacity(ordered_indices.len());
            let mut i = 0;
            idx = parent(idx);
            while i < ordered_indices.len() {
                new_indices.push(parent(ordered_indices[i]));
                let sibling = sibling(ordered_indices[i]);
                if i < ordered_indices.len() - 1 && ordered_indices[i + 1] == sibling {
                    i += 1;
                } else if sibling < self.nodes.len() {
                    proof.push(self.nodes[sibling].clone());
                }
                i += 1;
            }

            ordered_indices = new_indices.clone();
        }

        BatchPath {
            values: proof,
            indices,
            hasher: Default::default(),
        }
    }

    fn idx_of_leaf(&self, i: usize) -> usize {
        self.leaf_off + i
    }

    /// Convert a `MerkleTree` into a byte string, containint $8 + n * S$ where $n$ is the
    /// number of nodes and $S$ the output size of the hash function.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut result = Vec::with_capacity(4 + self.nodes.len() * D::output_size());
        result.extend_from_slice(
            &u32::try_from(self.n)
                .expect("Length must fit in u32")
                .to_be_bytes(),
        );
        for node in self.nodes.iter() {
            result.extend_from_slice(node);
        }
        result
    }

    /// Try to convert a byte string into a `MerkleTree`.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, MerkleTreeError> {
        let mut u32_bytes = [0u8; 4];
        u32_bytes.copy_from_slice(&bytes[..4]);
        let n = usize::try_from(u32::from_be_bytes(u32_bytes))
            .expect("Library should be build in 32 bit targets or higher");
        let num_nodes = n + n - 1;
        let mut nodes = Vec::with_capacity(num_nodes);
        for i in 0..num_nodes {
            nodes.push(bytes[4 + i * D::output_size()..4 + (i + 1) * D::output_size()].to_vec());
        }
        Ok(Self {
            nodes,
            leaf_off: num_nodes - n,
            n,
            hasher: PhantomData::default(),
        })
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
    use blake2::Blake2b;
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
        fn test_batch_proof((t, values) in arb_tree(64),
            selected in vec(any::<u8>(), 2..32)
        )  {
            let length = values.len();
            let mut batch_indices: Vec<usize> = selected.iter().map(|&v| v as usize % length).collect();
            batch_indices.sort_unstable();
            batch_indices.dedup();

            let batch_values = batch_indices.iter().map(|&v| values[v].clone()).collect::<Vec<_>>();
            let batch_proof = t.get_batched_path(batch_indices);

            let mt_commitment = t.to_commitment();
            assert!(mt_commitment.check_batched(&batch_values, &batch_proof).is_ok());
        }

        #[test]
        fn test_serde((t, values) in arb_tree(30)) {
            values.iter().enumerate().for_each(|(i, _v)| {
                let pf = t.get_path(i);
                assert!(t.to_commitment().check(&values[i], &pf).is_ok());

                let bytes = pf.to_bytes();
                let test2 = Path::<Blake2b>::from_bytes(&bytes).unwrap();
                assert!(t.to_commitment().check(&values[i], &test2).is_ok());

                let bytes = t.to_bytes();
                let test = MerkleTree::<Blake2b>::from_bytes(&bytes).unwrap();
                assert!(test.to_commitment().check(&values[i], &test2).is_ok());

                let bytes = t.to_commitment().to_bytes();
                let test = MerkleTreeCommitment::<Blake2b>::from_bytes(&bytes).unwrap();
                assert!(test.check(&values[i], &test2).is_ok());
            })
        }

        #[test]
        fn test_serde_batch_proof((t, values) in arb_tree(64),
            selected in vec(any::<u8>(), 2..32)
        )  {
            let length = values.len();
            let mut batch_indices: Vec<usize> = selected.iter().map(|&v| v as usize % length).collect();
            batch_indices.sort_unstable();
            batch_indices.dedup();

            let batch_values = batch_indices.iter().map(|&v| values[v].clone()).collect::<Vec<_>>();
            let batch_proof = t.get_batched_path(batch_indices);

            let proof_bytes = batch_proof.to_bytes();
            let proof = BatchPath::from_bytes(&proof_bytes).unwrap();

            let mt_commitment = t.to_commitment();
            assert!(mt_commitment.check_batched(&batch_values, &proof).is_ok());
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
    }
}
