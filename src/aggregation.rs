//! Aggregation module, which contains the mechanisms to compute and verify the
//! aggregate signatures and keys of an ATMS signature protocol.
//!
//! # Notation
//! An ATMS signature protocol relies on an underlying multi-signature.
//! For sake of simplicity we omit the `Setup`, `KeyGen`, `Sign` and `Verify` algorithms
//! from the underlying signature, and refer to the documentation available in the
//! [multi signatures implementation](./src/multi_sig).
//! Given a set $S$, denote by $\langle S\rangle$ a Merkle-tree commitment to the set $S$ created
//! in some fixed deterministic way. We divide the signers into two groups, eligible and
//! participants. The eligible signers, $Es$ with $|Es| = n$, are all those who are allowed to
//! participate in the signature process. We use all these keys to generate the master ATMS key.
//! The participating signers, $Ps$ with $|Ps| = d$, are
//! all those who participate in a particular signing procedure. We need $d$
//! to be larger than the threshold. Note that $Ps \subseteq Es$. Denote with $vk_i$ for $i \in Es$
//! the verification keys of all participants, and $\sigma_i$ for $i\in Ps$ the signatures produced
//! by the participating users.

#![allow(clippy::type_complexity)]

#[cfg(feature = "efficient-mtproof")]
use crate::merkle_tree::BatchPath;
#[cfg(not(feature = "efficient-mtproof"))]
use crate::merkle_tree::Path;
use crate::{
    error::{blst_err_to_atms, AtmsError},
    merkle_tree::{MerkleTree, MerkleTreeCommitment},
    multi_sig::{PublicKey, PublicKeyPoP, Signature},
};

use blake2::Digest;
use digest::FixedOutput;
use std::convert::TryFrom;
use std::{
    collections::{HashMap, HashSet},
    fmt::Debug,
};

/// An ATMS aggregate key, `Avk`, contains a vector commitment of all eligible signers, and the
/// aggregated key. Any third party with access to the public keys from all eligible signers can
/// generate an aggregate key.
///
/// Let $\mathcal{VK} = \lbrace vk_i\rbrace_{i\in Es}$.
///
/// $$ avk = \left(\sum_{i\in Es}vk_i, \langle \mathcal{VK}\rangle\right) $$
///
/// In order to generate an `Avk`, it is necessary to previously produce a valid registration
/// of all eligible signers. This guarantees that an `Avk` is only generated with keys
/// with a valid proof of possession. Otherwise, an adversary could produce what is known as
/// the "rogue key attack".
#[derive(Debug)]
pub struct Avk<H>
where
    H: Digest,
{
    /// The product of aggregated keys
    aggregate_key: PublicKey,
    /// The `MerkleTreeCommitment`
    mt_commitment: MerkleTreeCommitment<H>,
    /// Number of parties registered under this `AtmsAvk`
    nr_parties: usize,
}

impl<H: Digest> PartialEq for Avk<H> {
    fn eq(&self, other: &Self) -> bool {
        self.nr_parties == other.nr_parties
            && self.mt_commitment.value == other.mt_commitment.value
            && self.aggregate_key == other.aggregate_key
    }
}

impl<H: Digest> Eq for Avk<H> {}

impl<H> Avk<H>
where
    H: Digest + FixedOutput,
{
    /// In order to verify the correctness of a key aggregation, one simply recomputes the aggregation
    /// for a given set, and checks that it matches the expected value.
    /// # Error
    /// The function returns `AtmsError::InvalidPoP` if one of the proofs of possession is invalid,
    /// and `AtmsError::RegisterExistingKey` if the input tuple contains a repeated key.
    ///
    /// # Example
    /// ```
    /// # use atms::multi_sig::{PublicKeyPoP, SigningKey};
    /// # use atms::aggregation::Registration;
    /// # use atms::AtmsError;
    /// # use blake2::Blake2b;
    /// # use rand_core::OsRng;
    /// # fn main() -> Result<(), AtmsError> {
    /// let n = 10; // nr of eligible signers
    /// let threshold: usize = n - ((n - 1) / 3);
    /// let mut rng = OsRng;
    ///
    /// let mut keyspop: Vec<PublicKeyPoP> = Vec::with_capacity(n);
    /// for _ in 0..n {
    ///     let sk = SigningKey::gen(&mut rng);
    ///     let pkpop = PublicKeyPoP::from(&sk);
    ///     keyspop.push(pkpop);
    /// }
    ///
    /// let atms_registration = Registration::<Blake2b>::new(&keyspop)?;
    /// assert!(atms_registration.to_avk().check(&keyspop).is_ok());
    /// # Ok(())
    /// # }
    /// ```
    pub fn check(&self, keys: &[PublicKeyPoP]) -> Result<(), AtmsError> {
        let akey2: Registration<H> = Registration::new(keys)?;
        if self == &akey2.to_avk() {
            return Ok(());
        }
        Err(AtmsError::InvalidAggregation)
    }

    /// Convert `Avk` to byte string of size $48 + 8 + S$ where $S$ is the output size of the
    /// hash function.
    ///
    /// # Layout
    /// The layout of an `Avk` is
    /// * Aggregate key
    /// * Nr of parties
    /// * Merkle tree commitment
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut result = Vec::with_capacity(48 + 4 + H::output_size());
        result.extend_from_slice(&self.aggregate_key.to_bytes());
        result.extend_from_slice(
            &u32::try_from(self.nr_parties)
                .expect("Length must fit in u32")
                .to_be_bytes(),
        );
        result.extend_from_slice(&self.mt_commitment.to_bytes());
        result
    }

    /// Try to convert a byte string to an `Avk`. This function must be used in a setting
    /// where there exists a source of truth, and the verifier can check that the provided
    /// `Avk` is valid (e.g. through a signature of trusted authority).
    ///
    /// # Error
    /// Function fails if the byte representation corresponds to an invalid Avk
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, AtmsError> {
        let mut nr_bytes = [0u8; 4];
        nr_bytes.copy_from_slice(&bytes[48..52]);

        let aggregate_key = PublicKey::from_bytes(bytes)?;
        let nr_parties = usize::try_from(u32::from_be_bytes(nr_bytes))
            .expect("Library should be built in 32 bit targets or higher");
        let mt_commitment = MerkleTreeCommitment::from_bytes(&bytes[52..])?;
        Ok(Self {
            aggregate_key,
            mt_commitment,
            nr_parties,
        })
    }
}

/// An ATMS registration, which contains the aggregate key of all eligible signers, the Merkle
/// tree containing _all_ nodes in the tree (including the leaves), and a hash map, specifying
/// the position of each key in the merkle tree commitment.
#[derive(Debug)]
pub struct Registration<H>
where
    H: Digest + FixedOutput,
{
    /// The product of the aggregated keys
    aggregate_key: PublicKey,
    /// The Merkle tree containing the set of keys
    tree: MerkleTree<H>,
    /// Mapping to identify position of key within merkle tree
    leaf_map: HashMap<usize, PublicKey>,
}

/// An ATMS aggregate signature, contains the multi signature aggregation of all participating signers
/// and the public key of all non-participating signers, together with a proof of membership to the
/// vector commitment of all eligible signers.
#[derive(Debug)]
pub struct AggregateSig<H>
where
    H: Digest + FixedOutput,
{
    /// The product of the aggregated signatures
    aggregate: Signature,
    /// Non-signing keys
    pub keys: Vec<PublicKey>,
    #[cfg(feature = "efficient-mtproof")]
    /// Batch proof of membership of non-signing keys
    pub proof: Option<BatchPath<H>>,
    #[cfg(not(feature = "efficient-mtproof"))]
    /// Proof of membership of non-signing keys
    pub proof: Option<Vec<Path<H>>>,
}

impl<H> Registration<H>
where
    H: Digest + FixedOutput,
{
    /// Aggregate a set of keys, and commit to them in a canonical order. The canonical order
    /// is defined as the ordering of the byte representation of the compressed public keys. In
    /// practice, this ordering can be any deterministic function as long as the aggregator and
    /// the verifier use the same.
    ///
    /// Provided with a vector of keys with their proof of possession, `PublicKeyPoP`, the registration
    /// proceeds by checking all proofs of possession. Then, it aggregates all public key by adding
    /// them. Similarly, it commits to them by first ordering them, and then committing them in a
    /// Merkle Tree. Finally, it computes a hash map, by creating the relation of the relative
    /// position of each key in the committed vector. Registration guarantees that there are no
    /// repeated keys.
    ///
    /// # Error
    /// The function returns `AtmsError::InvalidPoP` if one of the proofs of possession is invalid,
    /// and `AtmsError::RegisterExistingKey` if the input tuple contains a repeated key.
    pub fn new(keys_pop: &[PublicKeyPoP]) -> Result<Self, AtmsError> {
        let mut checked_keys: Vec<PublicKey> = Vec::with_capacity(keys_pop.len());

        for key_pop in keys_pop {
            checked_keys.push(key_pop.verify()?);
        }

        let aggregate_key = checked_keys.iter().sum();

        // This ensures the order is the same for permutations of the input keys
        checked_keys.sort();

        let mut tree_vec = Vec::with_capacity(keys_pop.len());
        let mut leaf_map = HashMap::new();
        // todo: compress or serialize
        for (index, &key) in checked_keys.iter().enumerate() {
            if leaf_map.insert(index, key).is_some() {
                return Err(AtmsError::RegisterExistingKey(key));
            }
            tree_vec.push(key.0.compress().to_vec());
        }

        Ok(Registration {
            aggregate_key,
            tree: MerkleTree::create(&tree_vec),
            leaf_map,
        })
    }

    /// Returns the indices of the corresponding public key. The output vector is empty if the key is not
    /// part of the registration, and a tuple if the key is registered in several indices.
    ///
    /// # Example
    /// ```
    /// # use atms::multi_sig::{PublicKey, PublicKeyPoP, Signature, SigningKey};
    /// # use atms::aggregation::{AggregateSig, Registration};
    /// # use atms::AtmsError;
    /// # use blake2::Blake2b;
    /// # use rand_core::OsRng;
    /// # fn main() -> Result<(), AtmsError> {
    /// let mut rng = OsRng;
    /// let sk_1 = SigningKey::gen(&mut rng);
    /// let pk_1 = PublicKey::from(&sk_1);
    /// let pkpop_1 = PublicKeyPoP::from(&sk_1);
    /// let sk_2 = SigningKey::gen(&mut rng);
    /// let pk_2 = PublicKey::from(&sk_2);
    /// let pkpop_2 = PublicKeyPoP::from(&sk_2);
    ///
    /// let atms_registration = Registration::<Blake2b>::new(&[pkpop_1.clone(), pkpop_1.clone()])?;
    ///
    /// let mut indices_1 = atms_registration.get_index(&pk_1);
    /// indices_1.sort_unstable();
    /// assert_eq!(indices_1, vec![0,1]);
    ///
    /// let indices_2 = atms_registration.get_index(&pk_2);
    /// assert_eq!(indices_2, vec![]);
    /// # Ok(())
    /// # }
    pub fn get_index(&self, pk: &PublicKey) -> Vec<usize> {
        let mut indices = Vec::with_capacity(self.leaf_map.len());
        for (&idx, &reg_pk) in self.leaf_map.iter() {
            if reg_pk == *pk {
                indices.push(idx);
            }
        }
        indices
    }

    /// Return an `Avk` key from the key registration. This consists of the merkle root
    /// of the vector commitment, the aggregate key and the number of parties.
    pub fn to_avk(&self) -> Avk<H> {
        Avk {
            aggregate_key: self.aggregate_key,
            mt_commitment: self.tree.to_commitment(),
            nr_parties: self.leaf_map.len(),
        }
    }

    /// Convert a registration into a byte array. Not exposing serde of registration because
    /// passing the keys with PoP is cheaper and safer. This way we guarantee that a Registration
    /// can only be generated with valid keys.
    ///
    /// # Layout
    /// The layout of a `Registration` is:
    /// * Aggregate key
    /// * Number of registered parties
    /// * Hash map relating public keys to their position in the Merkle Tree commitment
    /// * Merkle Tree
    #[allow(dead_code)]
    fn to_bytes(&self) -> Vec<u8> {
        let mut result = Vec::with_capacity(
            48 + 4 + self.leaf_map.len() * (48 + 4) + 4 + self.tree.nodes.len() * H::output_size(),
        );
        result.extend_from_slice(&self.aggregate_key.to_bytes());
        let len = u32::try_from(self.leaf_map.len()).expect("Length must fit in u32");
        result.extend_from_slice(&len.to_be_bytes());
        for (&index, pk) in &self.leaf_map {
            result.extend_from_slice(&pk.to_bytes());
            result.extend_from_slice(
                &u32::try_from(index)
                    .expect("Index must fit in u32")
                    .to_be_bytes(),
            );
        }
        result.extend_from_slice(&self.tree.to_bytes());

        result
    }

    /// Try to convert a byte array into an ATMS `Registration`.  Not exposing serde of registration because
    /// passing the keys with PoP is cheaper and safer. This way we guarantee that a Registration
    /// can only be generated with valid keys.
    ///
    /// # Error
    /// Fails if the byte representation is an incorrect Registration.
    #[allow(dead_code)]
    fn from_bytes(bytes: &[u8]) -> Result<Self, AtmsError> {
        let aggregate_key = PublicKey::from_bytes(bytes)?;
        let mut len_bytes = [0u8; 4];
        len_bytes.copy_from_slice(&bytes[48..52]);
        let nr_parties = usize::try_from(u32::from_be_bytes(len_bytes))
            .expect("Library should be build in 32 bit targets or higher");
        let hm_element_size = 48 + 4; // pk size + u32 size
        let hm_offset = 52;
        let mut leaf_map = HashMap::new();
        for i in 0..nr_parties {
            let mut idx_bytes = [0u8; 4];
            idx_bytes.copy_from_slice(
                &bytes[hm_offset + hm_element_size * i + 48..hm_offset + hm_element_size * i + 52],
            );
            leaf_map.insert(
                usize::try_from(u32::from_be_bytes(idx_bytes))
                    .expect("Library should be build in 32 bit targets or higher"),
                PublicKey::from_bytes(&bytes[hm_offset + hm_element_size * i..])?,
            );
        }

        let mt_offset = hm_offset + hm_element_size * nr_parties;
        let tree = MerkleTree::from_bytes(&bytes[mt_offset..])?;
        Ok(Self {
            aggregate_key,
            tree,
            leaf_map,
        })
    }
}

impl<H> AggregateSig<H>
where
    H: Digest + FixedOutput,
{
    /// Aggregate a list of signatures.
    /// The signature aggregation can again be performed by any third party. Given $d$ pairs of
    /// signatures, `sigs`,  with their respective index representing the index in the merkle
    /// commitment, $\lbrace\sigma_i, id_i\rbrace_{i\in Ps}$,
    /// the aggregator produces the following aggregate signature. It begins by checking all signatures
    /// are valid, and which public keys
    /// are missing from the tuple of submitted signatures, $\widehat{vk}_i$, and computes their proof
    /// of set membership within the set of eligible signers, $\pi _{\widehat{vk_i}}$. Then it proceeds
    /// with the computation of the aggregate signature:
    ///
    /// $$ \sigma = \left(\sigma_a = \sum_{i\in Ps}\sigma_i, \lbrace\widehat{vk}_i\rbrace _{i\in Es \setminus Ps }, \lbrace\pi _{\widehat{vk_i}}\rbrace _{i\in Es \setminus Ps}\right).$$
    ///
    /// # Error
    /// Aggregation returns `AtmsError::NonRegisteredParticipant` if one of the submitted signatures
    /// comes from a non-registered participant, and `AtmsError::InvalidSignature` if one of the
    /// signatures is invalid.
    pub fn new(
        registration: &Registration<H>,
        sigs: &[(usize, Signature)],
        msg: &[u8],
    ) -> Result<Self, AtmsError> {
        let mut unique_sigs = sigs.to_vec();
        unique_sigs.sort_unstable();
        // make sure that we remove duplicate indices
        unique_sigs.dedup();

        let signers = unique_sigs.iter().map(|(k, _)| k).collect::<HashSet<_>>();
        let mut non_signer_indices = Vec::with_capacity(registration.tree.n - unique_sigs.len());
        let mut keys = (0..registration.tree.n)
            .into_iter()
            .filter_map(|k| {
                if !signers.contains(&k) {
                    non_signer_indices.push(k);
                    Some(*registration.leaf_map.get(&k)?)
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();

        let aggregate: Signature = unique_sigs
            .iter()
            .map(|&(index, s)| {
                if let Some(pk) = registration.leaf_map.get(&index) {
                    s.verify(pk, msg)?;
                    Ok(s)
                } else {
                    Err(AtmsError::NonRegisteredParticipant)
                }
            })
            .collect::<Result<Vec<Signature>, AtmsError>>()?
            .iter()
            .sum();

        let proof = if keys.is_empty() {
            None
        } else {
            #[cfg(feature = "efficient-mtproof")]
            {
                // We need to order keys and indices. Note that before committing to the keys
                // we order the slice, therefore the indices will be ordered with respect to the
                // keys
                keys.sort_unstable();
                non_signer_indices.sort_unstable();
                Some(registration.tree.get_batched_path(non_signer_indices))
            }
            #[cfg(not(feature = "efficient-mtproof"))]
            {
                keys.sort_unstable();
                non_signer_indices.sort_unstable();
                Some(
                    non_signer_indices
                        .iter()
                        .map(|&idx| registration.tree.get_path(idx))
                        .collect(),
                )
            }
        };

        Ok(Self {
            aggregate,
            keys,
            proof,
        })
    }

    /// Verify that this aggregation, `self`, is a valid signature of `msg` with respect to the
    /// aggregate key `avk` with the given `threshold`.
    /// The verifier takes as input a message `msg`, an
    /// aggregate key `avk`, a signature $\sigma$ and a `threshold` $t$, and proceeds as follows:
    /// 1. Verify that all public keys are different, and that they belong to the commitment $\langle
    ///    \mathcal{VK}\rangle$ in $avk$ using the proofs of membership.
    /// 2. Compute $avk'$ by dividing the aggregate key of non-signers, i.e.
    ///    $$avk' = avk - \sum_{i\in Es\setminus Ps}\widehat{vk_i}$$
    /// 3. Return valid if an only if $d\geq t$ and $\sigma$ validates with respect to $avk'$.
    ///
    /// # Error
    /// Verification failds in the following cases:
    /// * `AtmsError::FoundDuplicates` if there are duplicates in the non-signers,
    /// * `AtmsError::InvalidMerkleProof` if the proof of membership is invalid,
    /// * `AtmsError::TooMuchOutstandingSigners` if there are not enough signers, and
    /// * `AtmsError::InvalidSignature` if the signature is invalid.
    ///
    /// # Example
    /// ```
    /// # use atms::multi_sig::{PublicKey, PublicKeyPoP, Signature, SigningKey};
    /// # use atms::aggregation::{AggregateSig, Registration};
    /// # use atms::AtmsError;
    /// # use blake2::Blake2b;
    /// # use rand_core::OsRng;
    /// # fn main() -> Result<(), AtmsError> {
    /// let n = 10; // number of parties
    /// let subset_is = [1, 2, 3, 5, 6, 7, 9];
    /// let threshold: usize = n - ((n - 1) / 3);
    /// let msg = b"Did you know that Charles Babbage broke the Vigenere cipher?";
    /// let mut rng = OsRng;
    ///
    /// let mut sk_pks: Vec<(SigningKey, PublicKey)> = Vec::with_capacity(n);
    /// let mut keyspop: Vec<PublicKeyPoP> = Vec::with_capacity(n);
    /// let mut signatures: Vec<(usize, Signature)> = Vec::with_capacity(n);
    /// for _ in 0..n {
    ///     let sk = SigningKey::gen(&mut rng);
    ///     let pk = PublicKey::from(&sk);
    ///     let pkpop = PublicKeyPoP::from(&sk);
    ///     keyspop.push(pkpop);
    ///     sk_pks.push((sk, pk));
    /// }
    ///
    /// let atms_registration = Registration::<Blake2b>::new(&keyspop)?;
    ///
    /// for i in 0..n {
    ///     let (sk, pk) = &sk_pks[i];
    ///     let sig = sk.sign(msg);
    ///     assert!(sig.verify(pk, msg).is_ok());
    ///     let indices = atms_registration.get_index(pk);
    ///     for i in indices {
    ///         signatures.push((i, sig));
    ///     }
    /// }
    /// let avk = atms_registration.to_avk();
    /// assert!(avk.check(&keyspop).is_ok());
    ///
    /// let subset = subset_is
    ///     .iter()
    ///     .map(|i| {
    ///         signatures[i % n]
    ///     })
    ///     .collect::<Vec<_>>();
    ///
    /// let mut aggr_sig = AggregateSig::new(&atms_registration, &subset, msg).expect("Signatures should be valid");
    ///
    /// aggr_sig.verify(msg, &avk, threshold).unwrap();
    /// # Ok(())
    /// # }
    /// ```
    pub fn verify(&self, msg: &[u8], avk: &Avk<H>, threshold: usize) -> Result<(), AtmsError> {
        // The threshold must be higher than half the size of the parties.
        assert!(threshold > (avk.nr_parties / 2));

        if !self.keys.is_empty() {
            // Check inclusion proofs
            if let Some(proof) = &self.proof {
                let compressed_keys = self
                    .keys
                    .iter()
                    .map(|k| k.0.compress().to_vec())
                    .collect::<Vec<_>>();
                #[cfg(feature = "efficient-mtproof")]
                avk.mt_commitment.check_batched(&compressed_keys, proof)?;
                #[cfg(not(feature = "efficient-mtproof"))]
                {
                    for (key, proof) in compressed_keys.iter().zip(proof.iter()) {
                        avk.mt_commitment.check(key, proof)?;
                    }
                }
            } else {
                // Non-signers keys but no proof of membership.
                return Err(AtmsError::InvalidMerkleProof);
            }

            if self.keys.len() > avk.nr_parties - threshold {
                return Err(AtmsError::TooMuchOutstandingSigners(self.keys.len()));
            }
        }
        // Check with the underlying signature scheme that the quotient of the
        // aggregated key by the non-signers validates this signature.
        let final_key = avk.aggregate_key - self.keys.iter().sum();
        blst_err_to_atms(
            self.aggregate
                .0
                .verify(false, msg, &[], &[], &final_key.0, false),
        )
    }

    /// Convert to a byte string of size $8 + b * 8 + 96 + t * (48 + P)$, where $b$ is boolean which is
    /// 1 if there are non-signers, $t$ is the number of non-signers, and $P$ is the size of the proof
    /// of membership.
    ///
    /// # Layout
    /// The layout of an `AggregateSignature` is
    /// * Number of non-signers, $t$
    /// * Aggregate signature
    /// * $t$ public keys
    /// * Batch membership proof
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut aggregate_sig_bytes = Vec::new();
        let nr_non_signers = u32::try_from(self.keys.len()).expect("Length must fit in u32");
        aggregate_sig_bytes.extend_from_slice(&nr_non_signers.to_be_bytes());

        #[cfg(not(feature = "efficient-mtproof"))]
        if nr_non_signers > 0 {
            aggregate_sig_bytes.extend_from_slice(
                &u32::try_from(
                    self.proof
                        .as_ref()
                        .expect("If nr of non_signers is > 0, there will be a proof")[0]
                        .values
                        .len(),
                )
                .expect("Length must fit in u32")
                .to_be_bytes(),
            );
        }

        aggregate_sig_bytes.extend_from_slice(&self.aggregate.to_bytes());
        for key in &self.keys {
            aggregate_sig_bytes.extend_from_slice(&key.to_bytes());
        }

        if let Some(proof) = &self.proof {
            #[cfg(feature = "efficient-mtproof")]
            aggregate_sig_bytes.extend_from_slice(&proof.to_bytes());
            #[cfg(not(feature = "efficient-mtproof"))]
            for single_proof in proof.iter() {
                aggregate_sig_bytes.extend_from_slice(&single_proof.to_bytes());
            }
        }

        aggregate_sig_bytes
    }

    #[allow(unused_mut)]
    /// Deserialise a byte string to an `AggregateSig`.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, AtmsError> {
        let mut u32_bytes = [0u8; 4];
        u32_bytes.copy_from_slice(&bytes[..4]);
        let non_signers = usize::try_from(u32::from_be_bytes(u32_bytes))
            .expect("Library should be built in 32 bit targets or higher");

        let mut offset = 4;
        #[cfg(not(feature = "efficient-mtproof"))]
        {
            let mut size_proofs = 0;
            if non_signers > 0 {
                offset += 4;
                u32_bytes.copy_from_slice(&bytes[4..8]);
                // todo: properly handle this
                size_proofs = usize::try_from(u32::from_be_bytes(u32_bytes))
                    .expect("Library should be built in 32 bit targets or higher");
            }
        }

        let aggregate = Signature::from_bytes(&bytes[offset..])?;
        let mut keys: Vec<PublicKey> = Vec::with_capacity(non_signers);

        for i in 0..non_signers {
            let pk_offset = offset + 96 + i * 48;
            let pk = PublicKey::from_bytes(&bytes[pk_offset..])?;

            keys.push(pk);
        }

        let proof = if non_signers > 0 {
            let proof_offset = offset + 96 + non_signers * 48;
            #[cfg(feature = "efficient-mtproof")]
            {
                Some(BatchPath::from_bytes(&bytes[proof_offset..])?)
            }
            #[cfg(not(feature = "efficient-mtproof"))]
            {
                let proof_size = H::output_size() * size_proofs + 8; // plus 8 for the index and depth
                let mut mt_proofs = Vec::with_capacity(non_signers);
                for i in 0..non_signers {
                    mt_proofs.push(Path::from_bytes(&bytes[proof_offset + i * proof_size..])?);
                }
                Some(mt_proofs)
            }
        } else {
            None
        };

        Ok(Self {
            aggregate,
            keys,
            proof,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::multi_sig::{PublicKey, PublicKeyPoP, Signature, SigningKey};
    use blake2::Blake2b;

    use proptest::prelude::*;
    use rand::seq::SliceRandom;
    use rand_chacha::ChaCha20Rng;

    use rand_core::SeedableRng;
    proptest! {
        #![proptest_config(ProptestConfig::with_cases(1000))]

        #[test]
        fn test_aggregate_sig(msg in prop::collection::vec(any::<u8>(), 1..128),
                              num_sigs in 1..16usize,
                              seed in any::<[u8;32]>(),
        ) {
            let mut rng = ChaCha20Rng::from_seed(seed);
            let mut sk_pks = Vec::with_capacity(num_sigs);
            let mut pkpops = Vec::with_capacity(num_sigs);
            let mut sigs = Vec::with_capacity(num_sigs);
            for _ in 0..num_sigs {
                let sk = SigningKey::gen(&mut rng);
                let pk = PublicKey::from(&sk);
                let pkpop = PublicKeyPoP::from(&sk);
                pkpops.push(pkpop);
                sk_pks.push((sk, pk));
            }
            let registration = Registration::<Blake2b>::new(&pkpops).expect("Registration should pass with valid keys");

            for (sk, pk) in sk_pks {
                let sig = sk.sign(&msg);
                assert!(sig.verify(&pk, &msg).is_ok());
                let indices = registration.get_index(&pk);
                for j in indices {
                    sigs.push((j, sig));
                }
            }
            let mu = AggregateSig::new(&registration, &sigs, &msg).expect("Signatures should be valid");
            assert!(mu.verify(&msg, &registration.to_avk(), num_sigs).is_ok());
        }

        #[test]
        fn test_get_index(num_pks in 1..16usize,
                              num_eligible_signers in 1..20usize,
                              seed in any::<[u8;32]>(),
        ) {
            let mut rng = ChaCha20Rng::from_seed(seed);
            let mut sks = Vec::with_capacity(num_pks);
            let mut pks = Vec::with_capacity(num_eligible_signers);
            let mut pkpops = Vec::with_capacity(num_eligible_signers);
            for _ in 0..num_pks {
                let sk = SigningKey::gen(&mut rng);
                sks.push(sk);
            }

            for i in 0..num_eligible_signers {
                let pk = PublicKey::from(&sks[i % num_pks]);
                pks.push(pk);
                let pkpop = PublicKeyPoP::from(&sks[i % num_pks]);
                pkpops.push(pkpop);
            }
            pks.sort();

            let registration = Registration::<Blake2b>::new(&pkpops).expect("Registration should pass with valid keys");

            for (index, pk) in pks.iter().enumerate() {
                let indices = registration.get_index(pk);
                if indices.is_empty() {
                    panic!();
                } else {
                    assert!(indices.contains(&index));
                }
            }
        }

        #[test]
        fn test_aggregate_sig_repeaded_keys(msg in prop::collection::vec(any::<u8>(), 1..128),
                              num_sigs in 1..16usize,
                              num_pks in 1..8usize,
                              seed in any::<[u8;32]>(),
        ) {

            let mut rng = ChaCha20Rng::from_seed(seed);
            let mut sk_pks = Vec::with_capacity(num_pks);
            let mut pkpops = Vec::with_capacity(num_sigs);
            let mut sigs = Vec::with_capacity(num_sigs);
            for _ in 0..num_pks {
                let sk = SigningKey::gen(&mut rng);
                let pk = PublicKey::from(&sk);
                sk_pks.push((sk, pk));
            }

            for i in 0..num_sigs {
                pkpops.push(PublicKeyPoP::from(&sk_pks[i % num_pks].0));
            }

            let registration = Registration::<Blake2b>::new(&pkpops).expect("Registration should pass with valid keys");

            for (sk, pk) in sk_pks {
                let sig = sk.sign(&msg);
                assert!(sig.verify(&pk, &msg).is_ok());
                let indices = registration.get_index(&pk);
                for j in indices {
                    sigs.push((j, sig));
                }
            }
            let mu = AggregateSig::new(&registration, &sigs, &msg).expect("Signatures should be valid");
            assert!(mu.verify(&msg, &registration.to_avk(), num_sigs).is_ok());
        }

        #[test]
        fn test_aggregate_sig_serde(msg in prop::collection::vec(any::<u8>(), 1..128),
                              num_sigs in 1..16usize,
                              num_pks in 1..16usize,
                              seed in any::<[u8;32]>(),
        ) {
            let mut rng = ChaCha20Rng::from_seed(seed);
            let mut sk_pks = Vec::with_capacity(num_pks);
            let mut pkpops = Vec::with_capacity(num_pks);
            let mut sigs = Vec::with_capacity(num_sigs);
            for _ in 0..num_pks {
                let sk = SigningKey::gen(&mut rng);
                let pk = PublicKey::from(&sk);
                let pkpop = PublicKeyPoP::from(&sk);
                pkpops.push(pkpop);
                sk_pks.push((sk, pk));
            }
            let registration = Registration::<Blake2b>::new(&pkpops).expect("Registration should pass with valid keys");

            for i in 0..num_sigs {
                let (sk, pk) = &sk_pks[i % num_pks];
                let sig = sk.sign(&msg);
                assert!(sig.verify(pk, &msg).is_ok());
                let indices = registration.get_index(pk);
                for j in indices {
                    sigs.push((j, sig));
                }
            }
            let mu = AggregateSig::new(&registration, &sigs, &msg).expect("Signatures should be valid");
            let bytes = mu.to_bytes();
            let recovered = AggregateSig::<Blake2b>::from_bytes(&bytes).unwrap();
            match recovered.verify(&msg, &registration.to_avk(), num_pks - (num_pks - 1) / 3) {
                Ok(_) => {
                    assert!(num_sigs >= num_pks - (num_pks - 1) / 3);
                },
                Err(AtmsError::TooMuchOutstandingSigners(n)) => {
                    assert_eq!(n, num_pks - num_sigs);
                    assert!(n >=  (num_pks - 1) / 3);
                }
                Err(err) => {
                    unreachable!("{:?}", err);
                }
            }
        }

        #[test]
        fn test_aggregate_shuffled_sig(msg in prop::collection::vec(any::<u8>(), 1..128),
                              num_sigs in 1..16usize,
                              seed in any::<[u8;32]>(),
        ) {
            let mut rng = ChaCha20Rng::from_seed(seed);
            let mut sk_pks = Vec::with_capacity(num_sigs);
            let mut pkpops = Vec::with_capacity(num_sigs);
            let mut sigs = Vec::with_capacity(num_sigs);
            for _ in 0..num_sigs {
                let sk = SigningKey::gen(&mut rng);
                let pk = PublicKey::from(&sk);
                let pkpop = PublicKeyPoP::from(&sk);
                pkpops.push(pkpop);
                sk_pks.push((sk, pk));
            }
            let registration = Registration::<Blake2b>::new(&pkpops).expect("Registration should pass with valid keys");

            for (sk, pk) in sk_pks {
                let sig = sk.sign(&msg);
                assert!(sig.verify(&pk, &msg).is_ok());
                let indices = registration.get_index(&pk);
                for j in indices {
                    sigs.push((j, sig));
                }
            }

            sigs.shuffle(&mut rng);
            let mu = AggregateSig::new(&registration, &sigs, &msg).expect("Signatures should be valid");
            assert!(mu.verify(&msg, &registration.to_avk(), num_sigs).is_ok());
        }

        #[test]
        fn test_registration_serde(num_sigs in 1..16usize,
                              seed in any::<[u8;32]>(),
        ) {
            let mut rng = ChaCha20Rng::from_seed(seed);
            let mut pkpops = Vec::with_capacity(num_sigs);
            for _ in 0..num_sigs {
                let sk = SigningKey::gen(&mut rng);
                let pkpop = PublicKeyPoP::from(&sk);
                pkpops.push(pkpop);
            }
            let registration = Registration::<Blake2b>::new(&pkpops).expect("Registration should pass with valid keys");
            let bytes = registration.to_bytes();
            let test = Registration::<Blake2b>::from_bytes(&bytes).unwrap();
            assert!(test.to_avk().check(&pkpops).is_ok());
        }


        #[test]
        fn test_deaggregate_pks(msg in prop::collection::vec(any::<u8>(), 1..128),
                              num_pks in 1..16usize,
                              num_sigs in 1..5usize,
                              seed in any::<[u8;32]>(),
        ) {
            let mut rng = ChaCha20Rng::from_seed(seed);
            let mut sks = Vec::with_capacity(num_pks);
            let mut pks = Vec::with_capacity(num_pks);
            for _ in 0..num_pks {
                let sk = SigningKey::gen(&mut rng);
                let pk = PublicKey::from(&sk);
                sks.push(sk);
                pks.push(pk);
            }

            let mut aggr_pk = pks.iter().sum();
            let mut sigs = Vec::with_capacity(num_sigs);

            for sk in sks.iter().take(num_sigs as usize) {
                sigs.push(sk.sign(&msg));
            }

            for pk in pks.iter().skip(num_sigs as usize) {
                aggr_pk = aggr_pk - *pk;
            }

            let aggr_sig: Signature = sigs.iter().sum();
            assert!(aggr_sig.verify(&aggr_pk, &msg).is_ok());
        }

        #[test]
        fn test_correct_avk(num_pks in 1..16usize,
                              seed in any::<[u8;32]>(),
        ) {
            let mut rng = ChaCha20Rng::from_seed(seed);
            let mut sks = Vec::with_capacity(num_pks);
            let mut pks = Vec::with_capacity(num_pks);
            for _ in 0..num_pks {
                let sk = SigningKey::gen(&mut rng);
                let pk = PublicKeyPoP::from(&sk);
                sks.push(sk);
                pks.push(pk);
            }

            let registration = Registration::<Blake2b>::new(&pks).expect("Valid keys should have a valid registration.");
            assert!(registration.to_avk().check(&pks).is_ok());
        }

        #[test]
        fn test_avk_serde(num_pks in 1..16usize,
                              seed in any::<[u8;32]>(),
        ) {
            let mut rng = ChaCha20Rng::from_seed(seed);
            let mut sks = Vec::with_capacity(num_pks);
            let mut pks = Vec::with_capacity(num_pks);
            for _ in 0..num_pks {
                let sk = SigningKey::gen(&mut rng);
                let pk = PublicKeyPoP::from(&sk);
                sks.push(sk);
                pks.push(pk);
            }

            let avk = Registration::<Blake2b>::new(&pks).expect("Valid keys should have a valid registration.").to_avk();
            let bytes = avk.to_bytes();
            let test = Avk::<Blake2b>::from_bytes(&bytes).unwrap();
            assert!(test.check(&pks).is_ok());
        }

        #[test]
        fn shuffle_keys_same_avk(num_pks in 1..16usize,
                              seed in any::<[u8;32]>(),
        ) {
            let mut rng = ChaCha20Rng::from_seed(seed);
            let mut sks = Vec::with_capacity(num_pks);
            let mut pks = Vec::with_capacity(num_pks);
            for _ in 0..num_pks {
                let sk = SigningKey::gen(&mut rng);
                let pk = PublicKeyPoP::from(&sk);
                sks.push(sk);
                pks.push(pk);
            }

            let registration = Registration::<Blake2b>::new(&pks).expect("Valid keys should have a valid registration.");
            pks.shuffle(&mut rng);
            let shuffled_reg = Registration::<Blake2b>::new(&pks).expect("Shufled keys should have a correct registration.");
            assert_eq!(registration.to_avk(), shuffled_reg.to_avk());
            assert!(registration.to_avk().check(&pks).is_ok());
        }

        // todo: check whether we can use bool with proptest.
        #[test]
        fn test_atms_registration(n in 5..=32_usize,
                          seed in any::<[u8; 32]>(),
                          invalid_pop in 0..1,
                          repeated_reg in 0..1,
        ) {
            let mut rng = ChaCha20Rng::from_seed(seed);

            let mut keyspop: Vec<PublicKeyPoP> = Vec::with_capacity(n);
            for _ in 0..n {
                let sk = SigningKey::gen(&mut rng);
                let pkpop = PublicKeyPoP::from(&sk);
                keyspop.push(pkpop);
            }

            if repeated_reg == 1 {
                keyspop.push(keyspop[0]);
            }

            if invalid_pop == 1 {
                let sk = SigningKey::gen(&mut rng);
                let false_pkpop = PublicKeyPoP::from(&sk);
                keyspop[0] = false_pkpop;
            }

            match Registration::<Blake2b>::new(&keyspop) {
                Ok(_) => {
                    assert_eq!(0, invalid_pop);
                    assert_eq!(0, repeated_reg);
                },
                Err(AtmsError::RegisterExistingKey(key)) => {
                    assert_eq!(key, keyspop[0].0);
                    assert_eq!(repeated_reg, 1);
                },
                Err(AtmsError::InvalidPoP) => {
                    assert_eq!(invalid_pop, 1);
                },
                Err(err) => {
                    unreachable!("{:?}", err);
                }
            };
        }

        #[test]
        fn test_atms_aggregation(n in 5..=32_usize,
                          subset_is in prop::collection::vec(1..=32_usize, 1..=32_usize),
                          false_mk_proof in 0..32usize,
                          msg in any::<[u8; 16]>(),
                          seed in any::<[u8; 32]>(),
                          repeate_non_signer in 0..1,
        ) {
            let threshold: usize = n - ((n - 1) / 3);
            let mut rng = ChaCha20Rng::from_seed(seed);
            let mut sk_pks = Vec::with_capacity(n);
            let mut pkpops = Vec::with_capacity(n);
            let mut sigs = Vec::with_capacity(n);
            for _ in 0..n {
                let sk = SigningKey::gen(&mut rng);
                let pk = PublicKey::from(&sk);
                let pkpop = PublicKeyPoP::from(&sk);
                pkpops.push(pkpop);
                sk_pks.push((sk, pk));
            }

            let registration = Registration::<Blake2b>::new(&pkpops).expect("Re\
            gistration should pass with valid keys");

            for (sk, pk) in sk_pks {
                let sig = sk.sign(&msg);
                assert!(sig.verify(&pk, &msg).is_ok());
                let indices = registration.get_index(&pk);
                for j in indices {
                    sigs.push((j, sig));
                }
            }
            let mu = AggregateSig::new(&registration, &sigs, &msg).expect("Signatures should be valid");
            assert!(mu.verify(&msg, &registration.to_avk(), n).is_ok());

            // Note that we accept repeated signatures.
            let subset = subset_is
                .iter()
                .map(|i| {
                    sigs[i % n]
                })
                .collect::<Vec<_>>();

            let mut aggr_sig = AggregateSig::new(&registration, &subset, &msg).expect("Signatures should be valid");

            let mut false_susbset = subset.clone();
            false_susbset[0] = sigs[false_mk_proof % n];
            let false_aggr = AggregateSig::new(&registration, &false_susbset, &msg).expect("Signatures should be valid");
            if aggr_sig.keys.len() == false_aggr.keys.len() {
                aggr_sig.proof = false_aggr.proof.clone();
            }

            if aggr_sig.keys.len() == false_aggr.keys.len() && aggr_sig.keys.len() > 1 && repeate_non_signer == 1 {
                aggr_sig.keys[0] = false_aggr.keys[1];
                aggr_sig.proof = false_aggr.proof.clone();
            }

            let avk = registration.to_avk();
            match aggr_sig.verify(&msg, &avk, threshold) {
                Ok(()) => {
                    assert!(subset.len() >= threshold);
                    if aggr_sig.keys.len() > 1 && repeate_non_signer == 1 {
                        assert_eq!(aggr_sig.keys[0], false_aggr.keys[1]);
                    }
                },
                Err(AtmsError::TooMuchOutstandingSigners(d)) => {
                    assert!(d >= avk.nr_parties - threshold);
                }
                Err(AtmsError::InvalidMerkleProof) => {
                    assert!(false_susbset.to_vec() != subset || false_mk_proof % n != subset_is[0] || repeate_non_signer == 1);
                }
                Err(AtmsError::FoundDuplicates(pk)) => {
                    assert_eq!(repeate_non_signer, 1);
                    assert_eq!(pk, aggr_sig.keys[0]);
                }
                Err(err) => unreachable!("{:?}", err)
            }
        }
    }
}
