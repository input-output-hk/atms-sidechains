//! Multi signature module, which contains the wrappers around [blst](https://github.com/supranational/blst)
//! to build Boldryeva multi signature scheme.
//!
//! # Notation
//! We implement Boldryeva multi signatures over curve BLS12-381. Further reading
//! can be found [here](https://hackmd.io/@benjaminion/bls12-381) and the references thereof cited.
//! For level of detail required in this document, it is sufficient to understand that one can define
//! a pairing over BLS12-381, where a pairing is a map: $e:\mathbb{G}_1 \times \mathbb{G}_2 \rightarrow \mathbb{G}_T$, which satisfies the
//! following properties:
//!
//! * Bilinearity: $\forall a,b \in F^* _q$, $\forall P \in \mathbb{G}_1, Q \in \mathbb{G}_2: e(a* P,b* Q)=e(P,Q)^{ab}$
//! * Non-degeneracy: $e \neq 1$
//! * Computability: There exists an efficient algorithm to compute $e$
//!
//! where $\mathbb{G}_1, \mathbb{G}_2$ and $\mathbb{G}_T$ are three distinct groups of order a prime $q$. We
//! use additive notation for the operations over $\mathbb{G}_1, \mathbb{G}_2$ as the groups are defined
//! in an elliptic curve, while we use multiplicative notation for $\mathbb{G}_T$ as the latter is defined
//! in a multiplicative subgroup of an extension of $F_q$. We use $G_1, G_2$ to denote the generators of
//! $\mathbb{G}_1$ and $\mathbb{G}_2$ respectively. Finally, we use a hash function
//! $H_2: \lbrace 0,1\rbrace^* \rightarrow \mathbb{G}_2$ following the standardisation effort in the
//! [hashing to curves](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-14) standard draft.

use crate::error::{blst_err_to_atms, AtmsError};
use blst::min_pk::{
    AggregatePublicKey, AggregateSignature, PublicKey as BlstPk, SecretKey as BlstSk,
    Signature as BlstSig,
};
use blst::BLST_ERROR;
use rand_core::{CryptoRng, RngCore};
use std::{
    cmp::Ordering,
    fmt::Debug,
    hash::{Hash, Hasher},
    iter::Sum,
    ops::Sub,
};

/// Signing key.
#[derive(Debug)]
pub struct SigningKey(BlstSk);

/// Public Key.
#[derive(Clone, Copy, Debug)]
pub struct PublicKey(pub(crate) BlstPk);

/// Proof of possession, proving the correctness of a public key.
#[derive(Clone, Copy, Debug)]
pub struct ProofOfPossession(BlstSig);

/// A public key with its proof of possession.
#[derive(Clone, Copy, Debug)]
pub struct PublicKeyPoP(pub(crate) PublicKey, pub(crate) ProofOfPossession);

/// ATMS partial signature.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Signature(pub(crate) BlstSig);

impl SigningKey {
    /// Generate a new private key by choosing an integer uniformly at random from
    /// $\mathbb{Z}_q$.
    pub fn gen<R: CryptoRng + RngCore>(rng: &mut R) -> Self {
        let mut ikm = [0u8; 32];
        rng.fill_bytes(&mut ikm);
        Self(
            BlstSk::key_gen(&ikm, &[])
                .expect("Error occurs when the length of ikm < 32. This will not happen here."),
        )
    }

    /// Produce a partial signature for message `msg`. The signature, $\sigma$ is computed by hashing
    /// `msg` into $\mathbb{G}_2$ and multiplying by the secret key,  $\sigma = sk * H_2(msg)$.
    pub fn sign(&self, msg: &[u8]) -> Signature {
        Signature(self.0.sign(msg, &[], &[]))
    }

    /// Convert the secret key into byte string.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    /// Convert a string of bytes into a `SigningKey`.
    /// # Error
    /// Fails if the byte string represents a scalar larger than the group order.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, AtmsError> {
        match BlstSk::from_bytes(&bytes[..32]) {
            Ok(sk) => Ok(Self(sk)),
            Err(e) => Err(blst_err_to_atms(e)
                .expect_err("If deserialisation is not successful, blst returns and error different to SUCCESS."))
        }
    }
}

/// Create a `PublicKey` from a secret key, by returning $sk* G_1$.
impl From<&SigningKey> for PublicKey {
    fn from(sk: &SigningKey) -> Self {
        Self(sk.0.sk_to_pk())
    }
}

/// Create a `ProofOfPossession` from a secret key, by returning $sk* H_2(b"PoP")$.
impl From<&SigningKey> for ProofOfPossession {
    fn from(sk: &SigningKey) -> Self {
        ProofOfPossession(sk.0.sign(b"PoP", &[], &[]))
    }
}

/// Create a `PublicKeyPoP` by computing the public key and the proof of correctness and returning the
/// tuple.
impl From<&SigningKey> for PublicKeyPoP {
    fn from(sk: &SigningKey) -> Self {
        Self(PublicKey(sk.0.sk_to_pk()), sk.into())
    }
}

impl PublicKeyPoP {
    /// Verify the proof of possession with respect to the associated public key, by checking that
    /// $e(pk, H_2(b"PoP")) = e(G_1, \texttt{self})$, where `self` is the proof of possession.
    ///
    /// # Error
    /// Returns `InvalidPoP` in case the proof is invalid.
    ///
    /// # Example
    /// ```
    /// # use atms::multi_sig::{SigningKey, PublicKeyPoP};
    /// # use rand_core::OsRng;
    /// # fn main() {
    /// let sk = SigningKey::gen(&mut OsRng);
    /// let pkpop = PublicKeyPoP::from(&sk);
    /// assert!(pkpop.verify().is_ok());
    /// # }
    /// ```
    pub fn verify(&self) -> Result<PublicKey, AtmsError> {
        if self.1 .0.verify(false, b"PoP", &[], &[], &self.0 .0, false) == BLST_ERROR::BLST_SUCCESS
        {
            return Ok(self.0);
        }
        Err(AtmsError::InvalidPoP)
    }

    /// Convert to a 144 byte string.
    ///
    /// # Layout
    /// The layout of a `PublicKeyPoP` encoding is
    /// * Public key
    /// * Proof of Possession
    pub fn to_bytes(&self) -> [u8; 144] {
        let mut pkpop_bytes = [0u8; 144];
        pkpop_bytes[..48].copy_from_slice(&self.0.to_bytes());
        pkpop_bytes[48..].copy_from_slice(&self.1 .0.to_bytes());
        pkpop_bytes
    }

    /// Deserialise a byte string to a `PublicKeyPoP`.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, AtmsError> {
        let pk = match BlstPk::from_bytes(&bytes[..48]) {
            Ok(key) => PublicKey(key),
            Err(e) => {
                return Err(blst_err_to_atms(e).expect_err("If it passed, blst returns and error different to SUCCESS."))
            }
        };

        let pop = match BlstSig::from_bytes(&bytes[48..]) {
            Ok(proof) => ProofOfPossession(proof),
            Err(e) => {
                return Err(blst_err_to_atms(e).expect_err("If it passed, blst returns and error different to SUCCESS."))
            }
        };

        Ok(Self(pk, pop))
    }
}

impl PublicKey {
    /// Convert an `PublicKey` to its compressed byte representation.
    pub fn to_bytes(&self) -> [u8; 48] {
        self.0.to_bytes()
    }

    /// Convert a compressed byte string into a `PublicKey`.
    ///
    /// # Error
    /// This function fails if the bytes do not represent a compressed point of the curve.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, AtmsError> {
        match BlstPk::from_bytes(&bytes[..48]) {
            Ok(pk) => Ok(Self(pk)),
            Err(e) => Err(blst_err_to_atms(e)
                .expect_err("If deserialisation is not successful, blst returns and error different to SUCCESS."))
        }
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

// We need some unsafe code here due to what is being exposed in the rust FFI.
// todo: take particular care reviewing this
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
    /// Given a public key, $pk$, a signature, $\sigma$, and a message, $msg$, a verifier
    /// accepts the signature if the following check succeeds: $e(pk, H_2(msg)) = e(G_1, \sigma)$.
    ///
    /// # Error
    /// Function returns an error if the signature is invalid.
    ///
    /// # Example
    /// ```
    /// # use atms::multi_sig::{SigningKey, PublicKey};
    /// # use rand_core::OsRng;
    /// # fn main() {
    /// let msg = b".";
    /// let sk = SigningKey::gen(&mut OsRng);
    /// let pk = PublicKey::from(&sk);
    /// let sig = sk.sign(msg);
    /// assert!(sig.verify(&pk, msg).is_ok());
    /// # }
    /// ```
    pub fn verify(&self, pk: &PublicKey, msg: &[u8]) -> Result<(), AtmsError> {
        blst_err_to_atms(self.0.verify(false, msg, &[], &[], &pk.0, false))
    }

    /// Convert an `Signature` to its compressed byte representation.
    pub fn to_bytes(&self) -> [u8; 96] {
        self.0.to_bytes()
    }

    /// Convert a string of bytes into a `Signature`.
    /// # Error
    /// Returns an error if the byte string does not represent a point in the curve.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, AtmsError> {
        match BlstSig::from_bytes(&bytes[..96]) {
            Ok(sig) => Ok(Self(sig)),
            Err(e) => Err(blst_err_to_atms(e)
                .expect_err("If deserialisation is not successful, blst returns and error different to SUCCESS."))
        }
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

#[cfg(test)]
mod tests {
    use super::*;
    use blst::{
        blst_p1, blst_p1_add, blst_p1_add_affine, blst_p1_affine, blst_p1_cneg,
        blst_p1_deserialize, blst_p1_from_affine, blst_p1_serialize, blst_p1_uncompress, blst_p2,
        blst_p2_add_affine, blst_p2_affine, blst_p2_deserialize, blst_p2_serialize,
        blst_p2_uncompress, blst_scalar, blst_scalar_fr_check, blst_scalar_from_bendian,
    };
    use proptest::prelude::*;
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(1000))]

        #[test]
        fn test_gen(seed in any::<[u8; 32]>(),
        ) {
            let mut rng = ChaCha20Rng::from_seed(seed);
            let sk = SigningKey::gen(&mut rng);
            let pkpop = PublicKeyPoP::from(&sk);

            assert!(pkpop.verify().is_ok());
        }

        #[test]
        fn test_sig(
            msg in prop::collection::vec(any::<u8>(), 1..128),
            seed in any::<[u8;32]>(),
        ) {
            let sk = SigningKey::gen(&mut ChaCha20Rng::from_seed(seed));
            let pk = PublicKey::from(&sk);
            let sig = sk.sign(&msg);
            assert!(sig.verify(&pk, &msg).is_ok());
        }

        #[test]
        fn test_invalid_sig(msg in prop::collection::vec(any::<u8>(), 1..128),
                            seed in any::<[u8;32]>(),
        ) {
            let mut rng = ChaCha20Rng::from_seed(seed);
            let sk = SigningKey::gen(&mut rng);
            let pk = PublicKey::from(&sk);
            let sig = sk.sign(&msg);

            let invalid_sk = SigningKey::gen(&mut rng);
            let invalid_sig = invalid_sk.sign(&msg);
            assert_eq!(
                invalid_sig.verify(&pk, &msg).unwrap_err(),
                AtmsError::InvalidSignature
            );

            assert_eq!(
                sig.verify(
                    &pk,
                    b"We are just going to take a message long enough to make sure that \
                    the test is never going to fall in it. Therefore, the test should fail."
                    ).unwrap_err(),
                AtmsError::InvalidSignature)
        }

        #[test]
        fn addition_of_pks(nr_parties in 1..10usize,
            seed in any::<[u8;32]>())
        {
            let mut rng = ChaCha20Rng::from_seed(seed);
            let mut pks = Vec::with_capacity(nr_parties);
            let mut underlying_points = Vec::with_capacity(nr_parties);
            for _ in 0..nr_parties {
                let sk = SigningKey::gen(&mut rng);
                let pk = PublicKey::from(&sk);
                pks.push(pk);
                underlying_points.push(pk.0.serialize());
            }

            let aggr_pk: PublicKey = pks.iter().sum();

            unsafe {
                let mut aggr_point = blst_p1::default();
                let mut temp_point = blst_p1_affine::default();
                for point in underlying_points.iter() {
                    blst_p1_deserialize(&mut temp_point, &point[0]);
                    blst_p1_add_affine(&mut aggr_point, &aggr_point, &temp_point);
                }

                let mut bytes_res = [0u8; 96];
                blst_p1_serialize(&mut bytes_res[0], &aggr_point);
                assert_eq!(aggr_pk.0.serialize(), bytes_res);
            }
        }


        #[test]
        fn subtraction_of_pks(seed in any::<[u8;32]>())
        {
            let mut rng = ChaCha20Rng::from_seed(seed);
            let sk_1 = SigningKey::gen(&mut rng);
            let sk_2 = SigningKey::gen(&mut rng);
            let pk_1 = PublicKey::from(&sk_1);
            let pk_2 = PublicKey::from(&sk_2);
            let point_1 = pk_1.0.serialize();
            let point_2 = pk_2.0.serialize();

            let negation = pk_1 - pk_2;

            unsafe {
                let mut raw_negation = blst_p1::default();
                let mut raw_point_1 = blst_p1::default();
                let mut raw_point_2 = blst_p1::default();
                let mut raw_point_1_affine = blst_p1_affine::default();
                let mut raw_point_2_affine = blst_p1_affine::default();
                blst_p1_deserialize(&mut raw_point_1_affine, &point_1[0]);
                blst_p1_deserialize(&mut raw_point_2_affine, &point_2[0]);
                blst_p1_from_affine(&mut raw_point_1, &raw_point_1_affine);
                blst_p1_from_affine(&mut raw_point_2, &raw_point_2_affine);
                blst_p1_cneg(&mut raw_point_2, true);
                blst_p1_add(&mut raw_negation, &raw_point_1, &raw_point_2);

                let mut bytes_res = [0u8; 96];
                blst_p1_serialize(&mut bytes_res[0], &raw_negation);
                assert_eq!(negation.0.serialize(), bytes_res);
            }
        }

        #[test]
        fn addition_of_sigs(nr_parties in 1..10usize,
            seed in any::<[u8;32]>())
        {
            let mut rng = ChaCha20Rng::from_seed(seed);
            let mut sigs = Vec::with_capacity(nr_parties);
            let mut underlying_points = Vec::with_capacity(nr_parties);
            for _ in 0..nr_parties {
                let sk = SigningKey::gen(&mut rng);
                let sig = sk.sign(b"dummy message");
                sigs.push(sig);
                underlying_points.push(sig.0.serialize());
            }

            let aggr_sig: Signature = sigs.iter().sum();

            unsafe {
                let mut aggr_point = blst_p2::default();
                let mut temp_point = blst_p2_affine::default();
                for point in underlying_points.iter() {
                    blst_p2_deserialize(&mut temp_point, &point[0]);
                    blst_p2_add_affine(&mut aggr_point, &aggr_point, &temp_point);
                }

                let mut bytes_res = [0u8; 192];
                blst_p2_serialize(&mut bytes_res[0], &aggr_point);
                assert_eq!(aggr_sig.0.serialize(), bytes_res);
            }
        }

        #[test]
        fn pk_ordering(seed in any::<[u8;32]>()) {
            let mut rng = ChaCha20Rng::from_seed(seed);
            let sk_1 = SigningKey::gen(&mut rng);
            let sk_2 = SigningKey::gen(&mut rng);
            let pk_1 = PublicKey::from(&sk_1);
            let pk_2 = PublicKey::from(&sk_2);
            let pk_1_bytes = pk_1.to_bytes();
            let pk_2_bytes = pk_2.to_bytes();

            let mut result = Ordering::Equal;
            for (i, j) in pk_1_bytes.iter().zip(pk_2_bytes.iter()) {
                result = i.cmp(j);
                if result != Ordering::Equal {
                    break;
                }
            }
            assert_eq!(result, pk_1.cmp(&pk_2));
        }

        #[test]
        fn serde_sk(sk in any::<[u8;32]>()) {
            let mut raw_scalar = blst_scalar::default();
            unsafe {
                match SigningKey::from_bytes(&sk) {
                    Ok(_) => {
                        blst_scalar_from_bendian(&mut raw_scalar, &sk[0]);
                        assert!(blst_scalar_fr_check(&raw_scalar));
                    }
                    Err(_) => {
                        blst_scalar_from_bendian(&mut raw_scalar, &sk[0]);
                        assert!(!blst_scalar_fr_check(&raw_scalar));
                    },
                };
            }
        }

        #[test]
        fn serde_pk(seed in any::<[u8; 32]>()) {
            let mut random_bytes = [0u8; 48];
            ChaCha20Rng::from_seed(seed).fill_bytes(&mut random_bytes);
            let mut raw_pk = blst_p1_affine::default();
            unsafe{
                match PublicKey::from_bytes(&random_bytes) {
                    Ok(_) => {
                        assert_eq!(blst_p1_uncompress(&mut raw_pk, &random_bytes[0]), BLST_ERROR::BLST_SUCCESS);
                    }
                    Err(_) => {
                        let error = blst_p1_uncompress(&mut raw_pk, &random_bytes[0]);
                        assert!(error == BLST_ERROR::BLST_BAD_ENCODING || error == BLST_ERROR::BLST_POINT_NOT_ON_CURVE);
                    },
                };
            }
        }

        #[test]
        fn serde_sig(seed in any::<[u8; 32]>()) {
            let mut random_bytes = [0u8; 96];
            ChaCha20Rng::from_seed(seed).fill_bytes(&mut random_bytes);
            let mut raw_sig = blst_p2_affine::default();
            unsafe {
                match Signature::from_bytes(&random_bytes) {
                    Ok(_) => {
                        assert_eq!(blst_p2_uncompress(&mut raw_sig, &random_bytes[0]), BLST_ERROR::BLST_SUCCESS);
                    }
                    Err(_) => {
                        let error = blst_p2_uncompress(&mut raw_sig, &random_bytes[0]);
                        assert!(error == BLST_ERROR::BLST_BAD_ENCODING || error == BLST_ERROR::BLST_POINT_NOT_ON_CURVE);
                    },
                };
            }
        }
    }
}
