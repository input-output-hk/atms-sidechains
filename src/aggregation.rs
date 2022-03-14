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

use crate::{
    error::{blst_err_to_atms, AtmsError},
    merkle_tree::{MerkleTreeCommitment, Path},
    {MerkleTree, PublicKey, PublicKeyPoP, Signature},
};
use blake2::Digest;
use digest::FixedOutput;
use std::{
    collections::{HashMap, HashSet},
    fmt::Debug,
};

/// An ATMS aggregate key, `Avk`, contains a merkle tree commitment, and the aggregated key
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
    /// Check that this aggregation is derived from the given sequence of valid keys.
    pub fn check(&self, keys: &[PublicKeyPoP]) -> Result<(), AtmsError> {
        let akey2: Registration<H> = Registration::new(keys)?;
        if self == &akey2.to_avk() {
            return Ok(());
        }
        Err(AtmsError::InvalidAggregation)
    }

    /// Convert `Avk` to byte string.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut result = Vec::new();
        result.extend_from_slice(&self.aggregate_key.to_bytes());
        result.extend_from_slice(&self.nr_parties.to_be_bytes());
        result.extend_from_slice(&self.mt_commitment.to_bytes());
        result
    }

    /// Try to convert a byte string to an `Avk`.
    // todo: again, handle these conversions to usize..
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, AtmsError> {
        let mut nr_bytes = [0u8; 8];
        nr_bytes.copy_from_slice(&bytes[48..56]);

        let aggregate_key = PublicKey::from_bytes(bytes)?;
        let nr_parties = usize::from_be_bytes(nr_bytes);
        let mt_commitment = MerkleTreeCommitment::from_bytes(&bytes[56..])?;
        Ok(Self {
            aggregate_key,
            mt_commitment,
            nr_parties,
        })
    }
}

/// An ATMS registration
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
    leaf_map: HashMap<PublicKey, usize>,
}

/// An Aggregated Signature
///
/// Testing for docs
#[derive(Debug)]
pub struct AggregateSig<H>
where
    H: Digest + FixedOutput,
{
    /// The product of the aggregated signatures
    aggregate: Signature,
    /// Proofs of membership of non-signing keys
    pub keys_proofs: Vec<(PublicKey, Path<H>)>,
}

impl<H> Registration<H>
where
    H: Digest + FixedOutput,
{
    /// Aggregate a set of keys, and commit to them in a canonical order.
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
            if leaf_map.insert(key, index).is_some() {
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

    /// Return an `Avk` key from the key registration
    pub fn to_avk(&self) -> Avk<H> {
        Avk {
            aggregate_key: self.aggregate_key,
            mt_commitment: self.tree.to_commitment(),
            nr_parties: self.leaf_map.len(),
        }
    }

    /// Convert a registration into a byte array
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut result = Vec::new();
        result.extend_from_slice(&self.aggregate_key.to_bytes());
        result.extend_from_slice(&self.leaf_map.len().to_be_bytes());
        for (pk, index) in &self.leaf_map {
            result.extend_from_slice(&pk.to_bytes());
            result.extend_from_slice(&index.to_be_bytes());
        }
        result.extend_from_slice(&self.tree.to_bytes());

        result
    }

    /// Try to convert a byte array into an ATMS `Registration`
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, AtmsError> {
        let aggregate_key = PublicKey::from_bytes(bytes)?;
        let mut len_bytes = [0u8; 8];
        len_bytes.copy_from_slice(&bytes[48..56]);
        let nr_parties = u64::from_be_bytes(len_bytes) as usize;
        let hm_element_size = 48 + 8; // pk size + u64 size
        let hm_offset = 56;
        let mut leaf_map = HashMap::new();
        for i in 0..nr_parties {
            let mut idx_bytes = [0u8; 8];
            idx_bytes.copy_from_slice(
                &bytes[hm_offset + hm_element_size * i + 48..hm_offset + hm_element_size * i + 56],
            );
            leaf_map.insert(
                PublicKey::from_bytes(&bytes[hm_offset + hm_element_size * i..])?,
                usize::from_be_bytes(idx_bytes),
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
    // todo: do we want to pass the pks as part of the sigs, or maybe just some indices?
    pub fn new(
        registration: &Registration<H>,
        sigs: &[(PublicKey, Signature)],
        msg: &[u8],
    ) -> Result<Self, AtmsError> {
        let signers = sigs.iter().map(|(k, _)| k).collect::<HashSet<_>>();
        let keys_proofs = registration
            .leaf_map
            .keys()
            .filter_map(|&k| {
                if !signers.contains(&k) {
                    let &idx = registration.leaf_map.get(&k)?;
                    Some((k, registration.tree.get_path(idx)))
                } else {
                    None
                }
            })
            .collect::<Vec<(_, _)>>();

        let mut unique_sigs = sigs.to_vec();
        unique_sigs.sort_unstable();
        // make sure that we remove duplicates.
        unique_sigs.dedup();

        let aggregate: Signature = unique_sigs
            .iter()
            .map(|&(pk, s)| {
                if !registration.leaf_map.contains_key(&pk) {
                    return Err(AtmsError::NonRegisteredParticipant);
                }
                s.verify(&pk, msg)?;
                Ok(s)
            })
            .collect::<Result<Vec<Signature>, AtmsError>>()?
            .iter()
            .sum();
        Ok(Self {
            aggregate,
            keys_proofs,
        })
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
            if keys
                .mt_commitment
                .check(&non_signer.0.compress(), proof)
                .is_ok()
            {
                non_signing_size += 1;
                // Check non-signers are distinct
                if !unique_non_signers.insert(non_signer) {
                    return Err(AtmsError::FoundDuplicates(*non_signer));
                }
            } else {
                return Err(AtmsError::InvalidMerkleProof(*non_signer));
            }
        }

        // The threshold is k, for n = 3*k + 1
        assert!(keys.nr_parties - threshold as usize >= (keys.nr_parties - 1) / 3);
        if non_signing_size > keys.nr_parties - threshold {
            return Err(AtmsError::TooMuchOutstandingSigners(non_signing_size));
        }
        // Check with the underlying signature scheme that the quotient of the
        // aggregated key by the non-signers validates this signature.
        let final_key = keys.aggregate_key - unique_non_signers.into_iter().sum();
        blst_err_to_atms(
            self.aggregate
                .0
                .verify(false, msg, &[], &[], &final_key.0, false),
        )
    }

    /// Convert to a byte string.
    pub fn to_bytes(&self) -> Vec<u8> {
        // todo: lets do with_capacity here
        let mut aggregate_sig_bytes = Vec::new();
        let nr_non_signers = self.keys_proofs.len();
        aggregate_sig_bytes.extend_from_slice(&nr_non_signers.to_be_bytes());
        if nr_non_signers > 0 {
            aggregate_sig_bytes
                .extend_from_slice(&self.keys_proofs[0].1.values.len().to_be_bytes());
        }
        aggregate_sig_bytes.extend_from_slice(&self.aggregate.to_bytes());
        for (key, proof) in &self.keys_proofs {
            aggregate_sig_bytes.extend_from_slice(&key.to_bytes());
            aggregate_sig_bytes.extend_from_slice(&proof.to_bytes())
        }
        aggregate_sig_bytes
    }

    /// Deserialise a byte string to an `AggregateSig`.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, AtmsError> {
        let mut u64_bytes = [0u8; 8];
        u64_bytes.copy_from_slice(&bytes[..8]);
        // todo: properly handle this
        let size = u64::from_be_bytes(u64_bytes) as usize;
        let mut offset = 8;
        let mut size_proofs = 0;
        if size > 0 {
            offset += 8;
            u64_bytes.copy_from_slice(&bytes[8..16]);
            // todo: properly handle this
            size_proofs = u64::from_be_bytes(u64_bytes) as usize;
        }
        let aggregate = Signature::from_bytes(&bytes[offset..])?;
        let mut keys_proofs: Vec<(PublicKey, Path<H>)> = Vec::with_capacity(size);

        let pk_n_proof_size = 48 + H::output_size() * size_proofs + 16; // plus 16 for the index and depth
        for i in 0..size {
            let pk_offset = 112 + i * pk_n_proof_size;
            let proof_offset = pk_offset + 48;
            let pk = PublicKey::from_bytes(&bytes[pk_offset..])?;
            let proof = Path::from_bytes(&bytes[proof_offset..])?;
            keys_proofs.push((pk, proof));
        }

        Ok(Self {
            aggregate,
            keys_proofs,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{PublicKey, PublicKeyPoP, Signature, SigningKey};
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
            let mut pkpops = Vec::new();
            let mut sigs = Vec::new();
            for _ in 0..num_sigs {
                let sk = SigningKey::gen(&mut rng);
                let pk = PublicKey::from(&sk);
                let pkpop = PublicKeyPoP::from(&sk);
                let sig = sk.sign(&msg);
                assert!(sig.verify(&pk, &msg).is_ok());
                sigs.push((pk, sig));
                pkpops.push(pkpop);
            }
            let registration = Registration::<Blake2b>::new(&pkpops).expect("Registration should pass with valid keys");
            let mu = AggregateSig::new(&registration, &sigs, &msg).expect("Signatures should be valid");
            assert!(mu.verify(&msg, &registration.to_avk(), 0).is_ok());
        }

        #[test]
        fn test_aggregate_sig_serde(msg in prop::collection::vec(any::<u8>(), 1..128),
                              num_sigs in 1..16usize,
                              seed in any::<[u8;32]>(),
        ) {
            let mut rng = ChaCha20Rng::from_seed(seed);
            let mut pkpops = Vec::new();
            let mut sigs = Vec::new();
            for _ in 0..num_sigs {
                let sk = SigningKey::gen(&mut rng);
                let pk = PublicKey::from(&sk);
                let pkpop = PublicKeyPoP::from(&sk);
                let sig = sk.sign(&msg);
                assert!(sig.verify(&pk, &msg).is_ok());
                sigs.push((pk, sig));
                pkpops.push(pkpop);
            }
            let registration = Registration::<Blake2b>::new(&pkpops).expect("Registration should pass with valid keys");
            let mu = AggregateSig::new(&registration, &sigs, &msg).expect("Signatures should be valid");
            let bytes = mu.to_bytes();
            let recovered = AggregateSig::<Blake2b>::from_bytes(&bytes).unwrap();
            assert!(recovered.verify(&msg, &registration.to_avk(), 0).is_ok());
        }

        #[test]
        fn test_aggregate_shuffled_sig(msg in prop::collection::vec(any::<u8>(), 1..128),
                              num_sigs in 1..16usize,
                              seed in any::<[u8;32]>(),
        ) {
            let mut rng = ChaCha20Rng::from_seed(seed);
            let mut pkpops = Vec::new();
            let mut sigs = Vec::new();
            for _ in 0..num_sigs {
                let sk = SigningKey::gen(&mut rng);
                let pk = PublicKey::from(&sk);
                let pkpop = PublicKeyPoP::from(&sk);
                let sig = sk.sign(&msg);
                assert!(sig.verify(&pk, &msg).is_ok());
                sigs.push((pk, sig));
                pkpops.push(pkpop);
            }
            let registration = Registration::<Blake2b>::new(&pkpops).expect("Registration should pass with valid keys");
            sigs.shuffle(&mut rng);
            let mu = AggregateSig::new(&registration, &sigs, &msg).expect("Signatures should be valid");
            assert!(mu.verify(&msg, &registration.to_avk(), 0).is_ok());
        }

        #[test]
        fn test_registration_serde(num_sigs in 1..16usize,
                              seed in any::<[u8;32]>(),
        ) {
            let mut rng = ChaCha20Rng::from_seed(seed);
            let mut pkpops = Vec::new();
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
                              num_pks in 1..16,
                              num_sigs in 1..5,
                              seed in any::<[u8;32]>(),
        ) {
            let mut rng = ChaCha20Rng::from_seed(seed);
            let mut sks = Vec::new();
            let mut pks = Vec::new();
            for _ in 0..num_pks {
                let sk = SigningKey::gen(&mut rng);
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

        #[test]
        fn test_correct_avk(num_pks in 1..16,
                              seed in any::<[u8;32]>(),
        ) {
            let mut rng = ChaCha20Rng::from_seed(seed);
            let mut sks = Vec::new();
            let mut pks = Vec::new();
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
        fn test_avk_serde(num_pks in 1..16,
                              seed in any::<[u8;32]>(),
        ) {
            let mut rng = ChaCha20Rng::from_seed(seed);
            let mut sks = Vec::new();
            let mut pks = Vec::new();
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
        fn shuffle_keys_same_avk(num_pks in 1..16,
                              seed in any::<[u8;32]>(),
        ) {
            let mut rng = ChaCha20Rng::from_seed(seed);
            let mut sks = Vec::new();
            let mut pks = Vec::new();
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

            let mut keyspop: Vec<PublicKeyPoP> = Vec::new();
            for _ in 1..=n {
                let sk = SigningKey::gen(&mut rng);
                let pkpop = PublicKeyPoP::from(&sk);
                keyspop.push(pkpop);
            }

            if repeated_reg == 1 {
                keyspop.push(keyspop[0].clone());
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

            let mut keyspop: Vec<PublicKeyPoP> = Vec::new();
            let mut signatures: Vec<(PublicKey, Signature)> = Vec::new();
            for _ in 1..=n {
                let sk = SigningKey::gen(&mut rng);
                let pk = PublicKey::from(&sk);
                let pkpop = PublicKeyPoP::from(&sk);
                let sig = sk.sign(&msg);
                assert!(sig.verify(&pk, &msg).is_ok());
                keyspop.push(pkpop);
                signatures.push((pk, sig));
            }

            let atms_registration = Registration::<Blake2b>::new(&keyspop).expect("Registration should pass");
            let avk = atms_registration.to_avk();
            assert!(avk.check(&keyspop).is_ok());

            // Note that we accept repeated signatures.
            let subset = subset_is
                .iter()
                .map(|i| {
                    signatures[i % n]
                })
                .collect::<Vec<_>>();

            let mut aggr_sig = AggregateSig::new(&atms_registration, &subset, &msg).expect("Signatures should be valid");

            let false_susbset: [(PublicKey, Signature); 1] = [signatures[false_mk_proof % n]];
            let false_aggr = AggregateSig::new(&atms_registration, &false_susbset, &msg).expect("Signatures should be valid");
            if aggr_sig.keys_proofs.len() != 0 {
                aggr_sig.keys_proofs[0].1 = false_aggr.keys_proofs[0].1.clone();
            } else if aggr_sig.keys_proofs.len() > 1 && repeate_non_signer == 1 {
                aggr_sig.keys_proofs[0].0 = false_aggr.keys_proofs[1].0.clone();
                aggr_sig.keys_proofs[0].1 = false_aggr.keys_proofs[1].1.clone();
            }

            match aggr_sig.verify(&msg, &avk, threshold) {
                Ok(()) => {
                    assert!(subset.len() >= threshold);
                    if aggr_sig.keys_proofs.len() != 0 {
                        assert_eq!(aggr_sig.keys_proofs[0].0, false_aggr.keys_proofs[0].0);
                    }
                },
                Err(AtmsError::TooMuchOutstandingSigners(d)) => {
                    assert!(d >= avk.nr_parties - threshold);
                }
                Err(AtmsError::InvalidMerkleProof(pk)) => {
                    assert_eq!(pk, aggr_sig.keys_proofs[0].0);
                    assert_ne!(aggr_sig.keys_proofs[0].0, false_aggr.keys_proofs[0].0);
                }
                Err(AtmsError::FoundDuplicates(pk)) => {
                    assert_eq!(repeate_non_signer, 1);
                    assert_eq!(pk, aggr_sig.keys_proofs[0].0);
                }
                Err(err) => unreachable!("{:?}", err)
            }
        }
    }
}
