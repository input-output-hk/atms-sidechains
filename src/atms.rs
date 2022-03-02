//! Ad-Hoc Threshold MultiSignatures (ATMS) implementation.
//!
//! The implementation in this module is parameterized by the underlying
//! signature scheme, which will define its own type of key and signature.
//! The requirements of the unferlying signature scheme is that it provides the
//! functionality of aggregation both to the public keys as to the signatures.
//! We use multiplicative notation to represent this binary operation between
//! two instances.
//!
//! For sake of simplicity we omit the `Setup`, `KeyGen`, `Sign` and `Verify` algorithms
//! from the underlying signature, and refer to the documentation available in the
//! different multi signatures implementations ([msp](./src/msp),
//! [MuSig2](./src/examples/atms_musig2), or [naive Schnorr](./src/examples/atms_nsms)).
//!
//! # Notation
//! Given a set $S$, denote by $\langle S\rangle$ a Merkle-tree commitment to the set $S$ created
//! in some fixed deterministic way. We divide the signers into two groups, eligible and
//! participants. The eligible signers, $Es$ with $|Es| = n$, are all those who are allowed to
//! participate in the signature process. We use all these keys to generate the master ATMS key.
//! The participating signers, $Ps$ with $|Ps| = d$, are
//! all those who participate in a particular signing procedure. We need $d$
//! to be larger than the threshold. Note that $Ps \subseteq Es$. Denote with $vk_i$ for $i \in Es$
//! the verification keys of all participants, and $\sigma_i$ for $i\in Ps$ the signatures produced
//! by the participating users.
//!
//! # ATMS protocol
//! Any third party with access to the public keys from all eligible signers can generate an
//! aggregate key as follows. Let $\mathcal{VK} = \lbrace vk_i\rbrace_{i\in Es}$.
//!
//! $$ avk = \left(\prod_{i\in Es}vk_i, \langle \mathcal{VK}\rangle\right) $$
//!
//! In order to verify the correctness of a key aggregation, one simply recomputes the aggregation
//! for a given set, and checks that it matches the expected value.
//!
//! The signature aggregation can again be performed by any third party. Given $d$ pairs of
//! signatures with their respective public keys $\lbrace\sigma_i, vk_i\rbrace_{i\in Ps}$, and the remaining
//! $n-d$ keys of the non signers, $\lbrace\widehat{vk}_i\rbrace _{i\in Es \setminus Ps }$, the aggregator
//! produces the following aggregate signature
//!
//! $$ \sigma = \left(\sigma_a = \prod_{i\in Ps}\sigma_i, \lbrace\widehat{vk}_i\rbrace _{i\in Es \setminus Ps }, \lbrace\pi _{\widehat{vk_i}}\rbrace _{i\in Es \setminus Ps}\right)$$
//!
//! where $\pi_{\widehat{vk_i}}$ denotes the proof of membership of key $\widehat{vk_i}$ in the merkle
//! commitment.
//!
//! Finally, to verify an aggregate signature, the verifier takes as input a message $m$, an
//! aggregate key $avk$, and a signature $\sigma$ and proceeds as follows:
//! 1. Verify that all public keys are different, and that they belong to the commitment $\langle
//!    \mathcal{VK}\rangle$ in $avk$ using the proofs of membership.
//! 2. Compute $avk'$ by dividing the aggregate key of non-signers, i.e.
//!    $$avk' = \frac{avk}{\prod_{i\in Es\setminus Ps}\widehat{vk_i}}$$
//! 3. Return valid if an only if $d\geq t$ and the $\sigma_a$ validates with respect to $avk'$.
//!
//! # Example
//! The following is an example of usage using the MSP signature scheme.

#![allow(clippy::type_complexity)]

use crate::error::{blst_err_to_atms, AtmsError};
use crate::merkle_tree::*;
use blake2::digest::Digest;
use blst::min_pk::{
    AggregatePublicKey, AggregateSignature, PublicKey as BlstPk, SecretKey as BlstSk,
    Signature as BlstSig,
};
use blst::BLST_ERROR;
use rand_core::{CryptoRng, RngCore};
use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};
use std::fmt::Debug;
use std::hash::{Hash, Hasher};
use std::iter::Sum;
use std::ops::Sub;

/// Individual private key
#[derive(Debug)]
pub struct PrivateKey(BlstSk);

/// Individual public key
#[derive(Clone, Debug)]
pub struct PublicKey(BlstPk);

/// Proof of possession, proving the correctness of a public key
#[derive(Debug)]
pub struct ProofOfPossession(BlstSig);

/// A public key with its proof of possession
#[derive(Debug)]
pub struct PublicKeyPoP(PublicKey, ProofOfPossession);

/// ATMS partial signature.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Signature(BlstSig);

impl PrivateKey {
    /// Generate a new private key
    pub fn gen<R: CryptoRng + RngCore>(rng: &mut R) -> Self {
        let mut ikm = [0u8; 32];
        rng.fill_bytes(&mut ikm);
        Self(
            BlstSk::key_gen(&ikm, &[])
                .expect("Error occurs when the length of ikm < 32. This will not happen here."),
        )
    }

    /// Produce a partial signature
    pub fn sign(&self, msg: &[u8]) -> Signature {
        Signature(self.0.sign(msg, &[], &[]))
    }
}

impl PublicKeyPoP {
    /// Verify the proof of possession with respect to the associated public key.
    pub fn verify(&self) -> Result<PublicKey, AtmsError> {
        if self.1 .0.verify(false, b"PoP", &[], &[], &self.0 .0, false) == BLST_ERROR::BLST_SUCCESS
        {
            return Ok(self.0.clone());
        }
        Err(AtmsError::InvalidPoP)
    }
}

impl From<&PrivateKey> for PublicKey {
    fn from(sk: &PrivateKey) -> Self {
        Self(sk.0.sk_to_pk())
    }
}

impl From<&PrivateKey> for ProofOfPossession {
    fn from(sk: &PrivateKey) -> Self {
        ProofOfPossession(sk.0.sign(b"PoP", &[], &[]))
    }
}

impl From<&PrivateKey> for PublicKeyPoP {
    fn from(sk: &PrivateKey) -> Self {
        Self(PublicKey(sk.0.sk_to_pk()), sk.into())
    }
}

impl PublicKey {
    /// Convert an `AtmsPublicKey` to its compressed byte representation
    pub fn to_bytes(&self) -> [u8; 48] {
        self.0.to_bytes()
    }

    fn cmp_msp_mvk(&self, other: &PublicKey) -> Ordering {
        let self_bytes = self.to_bytes();
        let other_bytes = other.to_bytes();
        let mut result = Ordering::Equal;

        for (i, j) in self_bytes.iter().zip(other_bytes.iter()) {
            result = i.cmp(j);
            if result != Ordering::Equal {
                return result;
            }
        }

        result
    }
}

impl Hash for PublicKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        Hash::hash_slice(&self.0.compress(), state)
    }
}

// We need to implement PartialEq instead of deriving it because we are implementing Hash.
impl PartialEq for PublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl Eq for PublicKey {}

impl PartialOrd for PublicKey {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp_msp_mvk(other))
    }
}

impl Ord for PublicKey {
    fn cmp(&self, other: &Self) -> Ordering {
        self.cmp_msp_mvk(other)
    }
}

impl<'a> Sum<&'a Self> for PublicKey {
    fn sum<I>(iter: I) -> Self
    where
        I: Iterator<Item = &'a Self>,
    {
        let mut aggregate_key = BlstPk::default();
        let keys: Vec<&BlstPk> = iter.map(|x| &x.0).collect();

        if !keys.is_empty() {
            aggregate_key = AggregatePublicKey::aggregate(&keys, false)
                .expect("It is assumed that public keys are checked. If this aggregation failed is due to invalid keys.")
                .to_public_key();
        }

        Self(aggregate_key)
    }
}

/// We need some unsafe code here due to what is being exposed in the rust FFI.
/// todo: take particular care reviewing this
impl Sub for PublicKey {
    type Output = Self;
    fn sub(self, rhs: Self) -> PublicKey {
        use blst::{blst_bendian_from_fp, blst_fp, blst_fp_cneg, blst_fp_from_bendian};
        let mut rhs_bytes = rhs.0.serialize();
        unsafe {
            let y_bytes: Vec<u8> = rhs_bytes[48..].to_vec();
            let mut y: blst_fp = blst_fp::default();
            let mut neg_y: blst_fp = blst_fp::default();
            blst_fp_from_bendian(&mut y, &y_bytes[0]);
            blst_fp_cneg(&mut neg_y, &y, true);

            blst_bendian_from_fp(&mut rhs_bytes[48], &neg_y);
        }
        let neg_rhs = BlstPk::deserialize(&rhs_bytes)
            .expect("The negative of a valid point is also a valid point.");
        PublicKey(
            AggregatePublicKey::aggregate(&[&neg_rhs, &self.0], false)
                .expect("Points are valid")
                .to_public_key(),
        )
    }
}

impl Signature {
    /// Verify a signature
    pub fn verify(&self, pk: &PublicKey, msg: &[u8]) -> Result<(), AtmsError> {
        blst_err_to_atms(self.0.verify(false, msg, &[], &[], &pk.0, false))
    }

    /// Convert an `AtmsSignature` to its compressed byte representation.
    pub fn to_bytes(&self) -> [u8; 96] {
        self.0.to_bytes()
    }

    fn cmp_msp_sig(&self, other: &Self) -> Ordering {
        let self_bytes = self.to_bytes();
        let other_bytes = other.to_bytes();
        let mut result = Ordering::Equal;

        for (i, j) in self_bytes.iter().zip(other_bytes.iter()) {
            result = i.cmp(j);
            if result != Ordering::Equal {
                return result;
            }
        }
        result
    }
}

impl PartialOrd for Signature {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp_msp_sig(other))
    }
}

impl Ord for Signature {
    fn cmp(&self, other: &Self) -> Ordering {
        self.cmp_msp_sig(other)
    }
}

impl<'a> Sum<&'a Self> for Signature {
    fn sum<I>(iter: I) -> Self
    where
        I: Iterator<Item = &'a Self>,
    {
        let signatures: Vec<&BlstSig> = iter.map(|x| &x.0).collect();
        let aggregate = AggregateSignature::aggregate(&signatures, false).expect("Signatures are assumed verified before aggregation. If signatures are invalid, they should not be aggregated.");
        Self(aggregate.to_signature())
    }
}

/// An ATMS aggregate key, `Avk`, contains a merkle tree commitment, and the aggregated key
#[derive(Debug)]
pub struct Avk<H>
where
    H: MTHashLeaf + Digest,
{
    /// The product of aggregated keys
    aggregate_key: PublicKey,
    /// The `MerkleTreeCommitment`
    mt_commitment: MerkleTreeCommitment<H>,
    /// Number of parties registered under this `AtmsAvk`
    nr_parties: usize,
}

impl<H> Avk<H>
where
    H: MTHashLeaf + Digest,
{
    /// Check that this aggregation is derived from the given sequence of valid keys.
    pub fn check(&self, keys: &[PublicKeyPoP]) -> Result<(), AtmsError> {
        let akey2: Registration<H> = Registration::new(keys, 0)?;
        if &self.mt_commitment.value == akey2.tree.root()
            && self.aggregate_key == akey2.aggregate_key
        {
            return Ok(());
        }
        Err(AtmsError::InvalidAggregation)
    }
}

/// An ATMS registration
#[derive(Debug)]
pub struct Registration<H>
where
    H: MTHashLeaf + Digest,
{
    /// The product of the aggregated keys
    aggregate_key: PublicKey,
    /// The Merkle tree containing the set of keys
    tree: MerkleTree<H>,
    /// Mapping to identify position of key within merkle tree
    leaf_map: HashMap<PublicKey, usize>,
    /// Threshold of parties required to validate a signature
    threshold: usize,
}

/// An Aggregated Signature
#[derive(Debug)]
pub struct AggregateSig<H>
where
    H: MTHashLeaf + Digest,
{
    /// The product of the aggregated signatures
    aggregate: Signature,
    /// Proofs of membership of non-signing keys
    keys_proofs: Vec<(PublicKey, Path<H::F>)>,
}

impl<H> Registration<H>
where
    H: MTHashLeaf + Digest,
{
    /// Aggregate a set of keys, and commit to them in a canonical order.
    pub fn new(keys_pop: &[PublicKeyPoP], threshold: usize) -> Result<Self, AtmsError> {
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
        for (index, key) in checked_keys.iter().enumerate() {
            if leaf_map.insert(key.clone(), index).is_some() {
                return Err(AtmsError::ExistingKey(key.clone()));
            }
            tree_vec.push(key.0.compress().to_vec());
        }

        Ok(Registration {
            aggregate_key,
            tree: MerkleTree::create(&tree_vec),
            leaf_map,
            threshold,
        })
    }

    /// Return an `Avk` key from the key registration
    pub fn to_avk(&self) -> Avk<H> {
        Avk {
            aggregate_key: self.aggregate_key.clone(),
            mt_commitment: self.tree.to_commitment(),
            nr_parties: self.leaf_map.len(),
        }
    }
}

impl<H> AggregateSig<H>
where
    H: MTHashLeaf + Digest,
{
    /// Aggregate a list of signatures.
    // todo: we probably want to verify all signatures
    // todo: do we want to pass the pks as part of the sigs, or maybe just some indices?
    pub fn new(registration: &Registration<H>, sigs: &[(PublicKey, Signature)]) -> Self {
        let signers = sigs.iter().map(|(k, _)| k).collect::<HashSet<_>>();
        let keys_proofs = registration
            .leaf_map
            .keys()
            .filter_map(|k| {
                if !signers.contains(k) {
                    let &idx = registration.leaf_map.get(k)?;
                    Some((k.clone(), registration.tree.get_path(idx)))
                } else {
                    None
                }
            })
            .collect::<Vec<(_, _)>>();

        let mut unique_sigs = sigs.to_vec();
        unique_sigs.sort_unstable();
        // make sure that we don't have duplicates.
        unique_sigs.dedup();

        let aggregate: Signature = unique_sigs.iter().map(|(_, s)| s).sum();
        Self {
            aggregate,
            keys_proofs,
        }
    }

    /// Verify that this aggregation is valid for the given collection of keys and message.
    pub fn verify(&self, msg: &[u8], keys: &Avk<H>, threshold: usize) -> Result<(), AtmsError> {
        // Check duplicates by building this set of
        // non-signing keys
        let mut unique_non_signers = HashSet::new();
        let mut non_signing_size = 0;

        // Check inclusion proofs
        // todo: best compress or serialize?
        for (non_signer, proof) in &self.keys_proofs {
            if keys.mt_commitment.check(&non_signer.0.compress(), proof) {
                non_signing_size += 1;
                // Check non-signers are distinct
                if !unique_non_signers.insert(non_signer) {
                    return Err(AtmsError::FoundDuplicates(non_signer.clone()));
                }
            } else {
                return Err(AtmsError::InvalidMerkleProof(non_signer.clone()));
            }
        }

        // The threshold is k, for n = 3*k + 1
        assert!(keys.nr_parties - threshold as usize >= (keys.nr_parties - 1) / 3);
        if non_signing_size > keys.nr_parties - threshold {
            return Err(AtmsError::TooMuchOutstandingSigners(non_signing_size));
        }
        // Check with the underlying signature scheme that the quotient of the
        // aggregated key by the non-signers validates this signature.
        let final_key = keys.aggregate_key.clone() - unique_non_signers.into_iter().sum();
        blst_err_to_atms(
            self.aggregate
                .0
                .verify(false, msg, &[], &[], &final_key.0, false),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use blake2::Blake2b;
    use blst::min_sig::SecretKey;
    use proptest::prelude::*;
    use rand_chacha::ChaCha20Rng;
    use rand_core::{OsRng, SeedableRng};

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(1000))]

        #[test]
        fn test_sig(
            msg in prop::collection::vec(any::<u8>(), 1..128),
            seed in any::<[u8;32]>(),
        ) {
            let sk = PrivateKey::gen(&mut ChaCha20Rng::from_seed(seed));
            let pk = PublicKey::from(&sk);
            let sig = sk.sign(&msg);
            assert!(sig.verify(&pk, &msg).is_ok());
        }

        #[test]
        fn test_invalid_sig(msg in prop::collection::vec(any::<u8>(), 1..128),
                            seed in any::<[u8;32]>(),
        ) {
            let mut rng = ChaCha20Rng::from_seed(seed);
            let sk = PrivateKey::gen(&mut rng);
            let pk = PublicKey::from(&sk);

            let invalid_sk = PrivateKey::gen(&mut rng);
            let invalid_sig = invalid_sk.sign(&msg);
            assert!(invalid_sig.verify(&pk, &msg).is_err());
        }

        #[test]
        fn test_aggregate_sig(msg in prop::collection::vec(any::<u8>(), 1..128),
                              num_sigs in 1..16usize,
                              seed in any::<[u8;32]>(),
        ) {
            let mut rng = ChaCha20Rng::from_seed(seed);
            let mut pkpops = Vec::new();
            let mut sigs = Vec::new();
            for _ in 0..num_sigs {
                let sk = PrivateKey::gen(&mut rng);
                let pk = PublicKey::from(&sk);
                let pkpop = PublicKeyPoP::from(&sk);
                let sig = sk.sign(&msg);
                assert!(sig.verify(&pk, &msg).is_ok());
                sigs.push((pk, sig));
                pkpops.push(pkpop);
            }
            let registration = Registration::<Blake2b>::new(&pkpops, 0).expect("Registration should pass with valid keys");
            let mu = AggregateSig::new(&registration, &sigs);
            assert!(mu.verify(&msg, &registration.to_avk(), 0).is_ok());
        }

        #[test]
        fn test_deaggregate_pks(msg in prop::collection::vec(any::<u8>(), 1..128),
                              num_pks in 1..16,
                              num_sigs in 1..5,
                              seed in any::<[u8;32]>(),
        ) {
            let mut rng = ChaCha20Rng::from_seed(seed);
            let mut sks = Vec::new();
            let mut pks = Vec::new();
            for _ in 0..num_pks {
                let sk = PrivateKey::gen(&mut rng);
                let pk = PublicKey::from(&sk);
                sks.push(sk);
                pks.push(pk);
            }

            let mut aggr_pk = pks.iter().sum();
            let mut sigs = Vec::new();

            for sk in sks.iter().take(num_sigs as usize) {
                sigs.push(sk.sign(&msg));
            }

            for pk in pks.iter().skip(num_sigs as usize) {
                aggr_pk = aggr_pk - pk.clone();
            }

            let aggr_sig: Signature = sigs.iter().sum();
            assert!(aggr_sig.verify(&aggr_pk, &msg).is_ok());
        }
    }

    #[test]
    fn test_gen() {
        for _ in 0..128 {
            let sk = PrivateKey::gen(&mut OsRng);
            let pkpop = PublicKeyPoP::from(&sk);

            assert!(pkpop.verify().is_ok());
        }
    }
}
