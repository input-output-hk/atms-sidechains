use crate::error::{blst_err_to_atms, AtmsError};
use blst::min_pk::{
    AggregatePublicKey, AggregateSignature, PublicKey as BlstPk, SecretKey as BlstSk,
    Signature as BlstSig,
};
use blst::BLST_ERROR;
use rand_core::{CryptoRng, RngCore};
use std::cmp::Ordering;
use std::fmt::Debug;
use std::hash::{Hash, Hasher};
use std::iter::Sum;
use std::ops::Sub;

/// Individual private key
#[derive(Debug)]
pub struct SigningKey(BlstSk);

/// Individual public key
#[derive(Clone, Copy, Debug)]
pub struct PublicKey(pub(crate) BlstPk);

/// Proof of possession, proving the correctness of a public key
#[derive(Clone, Copy, Debug)]
pub struct ProofOfPossession(BlstSig);

/// A public key with its proof of possession
#[derive(Clone, Copy, Debug)]
pub struct PublicKeyPoP(pub(crate) PublicKey, pub(crate) ProofOfPossession);

/// ATMS partial signature.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Signature(pub(crate) BlstSig);

impl SigningKey {
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
            return Ok(self.0);
        }
        Err(AtmsError::InvalidPoP)
    }
}

impl From<&SigningKey> for PublicKey {
    fn from(sk: &SigningKey) -> Self {
        Self(sk.0.sk_to_pk())
    }
}

impl From<&SigningKey> for ProofOfPossession {
    fn from(sk: &SigningKey) -> Self {
        ProofOfPossession(sk.0.sign(b"PoP", &[], &[]))
    }
}

impl From<&SigningKey> for PublicKeyPoP {
    fn from(sk: &SigningKey) -> Self {
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

#[cfg(test)]
mod tests {
    use super::*;
    use blst::{blst_p1, blst_p1_cneg, blst_p1_add, blst_p1_add_affine, blst_p1_affine, blst_p1_deserialize, blst_p1_from_affine, blst_p1_serialize, blst_p2, blst_p2_add_affine, blst_p2_affine, blst_p2_deserialize, blst_p2_serialize};
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
            let mut pks = Vec::new();
            let mut underlying_points = Vec::new();
            for _ in 0..nr_parties {
                let sk = SigningKey::gen(&mut rng);
                let pk = PublicKey::from(&sk);
                pks.push(pk.clone());
                underlying_points.push(pk.0.serialize());
            }

            let aggr_pk: PublicKey = pks.iter().sum();

            unsafe {
                let mut aggr_point = blst_p1::default();
                let mut temp_point = blst_p1_affine::default();
                for i in 0..nr_parties {
                    blst_p1_deserialize(&mut temp_point, &underlying_points[i][0]);
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
            let mut sigs = Vec::new();
            let mut underlying_points = Vec::new();
            for _ in 0..nr_parties {
                let sk = SigningKey::gen(&mut rng);
                let sig = sk.sign(b"dummy message");
                sigs.push(sig.clone());
                underlying_points.push(sig.0.serialize());
            }

            let aggr_sig: Signature = sigs.iter().sum();

            unsafe {
                let mut aggr_point = blst_p2::default();
                let mut temp_point = blst_p2_affine::default();
                for i in 0..nr_parties {
                    blst_p2_deserialize(&mut temp_point, &underlying_points[i][0]);
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
                result = i.cmp(&j);
                if result != Ordering::Equal {
                    break;
                }
            }
            assert_eq!(result, pk_1.cmp(&pk_2));
        }
    }
}
