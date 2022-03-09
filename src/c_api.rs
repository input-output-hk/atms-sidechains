//! C api. All functions return an i64, with 0 upon success, and -99 if the returned pointer
//! is null. Other error codes are function dependent.
use crate::{AggregateSig, Registration, Signature, SigningKey, PublicKey, PublicKeyPoP, ProofOfPossession};
use rand_core::OsRng;
use std::{
    ffi::CStr,
    os::raw::c_char
};

pub const NULLPOINTERERR: i64 = -99;

type H = blake2::Blake2b;
type SigningKeyPtr = *mut SigningKey;
type PublicKeyPoPPtr = *mut PublicKeyPoP;
type PublicKeyPtr = *mut PublicKey;
type SignaturePtr = *mut Signature;
type RegistrationPtr = *mut Registration<H>;
type AggregateSigPtr = *mut AggregateSig<H>;


/// Frees a signature pointer
macro_rules! free_pointer {
    ($type_name:ident, $pointer_type:ty)=> {
        paste::item! {
            #[no_mangle]
            pub extern "C" fn [< free_ $type_name>](p: $pointer_type) -> i64 {
                unsafe {
                    if let Some(p) = p.as_mut() {
                        Box::from_raw(p);
                        return 0;
                    }
                    NULLPOINTERERR
                }
            }
        }
    }
}

free_pointer!(signature, SignaturePtr);
free_pointer!(sk, SigningKeyPtr);
free_pointer!(pk, PublicKeyPtr);
free_pointer!(pkpop, PublicKeyPoPPtr);
free_pointer!(registration, RegistrationPtr);
free_pointer!(aggr_sig, AggregateSigPtr);

// A macro would be nice for the below, but macros do not
// seem to work properly with cbindgen:

use std::{intrinsics::copy_nonoverlapping, slice};
/// Serialisation functions
macro_rules! atms_serialisation {
    ($type_name:ident, $pointer_type:ty, $struct_type:ty)=> {
        paste::item! {
            #[no_mangle]
            pub extern "C" fn [< serialize_ $type_name>]
            (p: $pointer_type, out_size: *mut usize, out_bytes: *mut *mut u8) -> i64
            {
                unsafe {
                    if let (Some(v), Some(size_checked), Some(out_checked)) =
                    (p.as_ref(), out_size.as_mut(), out_bytes.as_mut())
                    {
                        let bytes = v.to_bytes();
                        let len = bytes.len();
                        *size_checked = len;
                        let dst = libc::malloc(len) as *mut u8;
                        copy_nonoverlapping(bytes.as_ptr(), dst, len);
                        *out_checked = dst;
                        return 0;
                    }
                    NULLPOINTERERR
                }
            }

            /// Deserialize a byte string.
            #[no_mangle]
            pub extern "C" fn [< deserialize_ $type_name>]
            (size: usize, bytes: *const u8, result: *mut $pointer_type) -> i64 {
                unsafe {
                    if let (Some(res), Some(bytes)) = (result.as_mut(), bytes.as_ref()) {
                        let val = $struct_type::from_bytes(slice::from_raw_parts(bytes, size)).unwrap();
                        *res = Box::into_raw(Box::new(val));
                        return 0;
                    }
                    NULLPOINTERERR
                }
            }
        }
    }
}

atms_serialisation!(signature, SignaturePtr, Signature);
atms_serialisation!(sk, SigningKeyPtr, SigningKey);
atms_serialisation!(pk, PublicKeyPtr, PublicKey);
atms_serialisation!(pkpop, PublicKeyPoPPtr, PublicKeyPoP);
atms_serialisation!(registration, RegistrationPtr, Registration);
atms_serialisation!(aggr_sig, AggregateSigPtr, AggregateSig);

// mod msp {
//     use super::*;
//     use crate::msp::Msp;
//
//     #[no_mangle]
//     pub extern "C" fn msp_generate_keypair(sk_ptr: *mut MspSkPtr, pk_ptr: *mut MspPkPtr) -> i64 {
//         let mut rng = OsRng::default();
//         let (sk, pk) = Msp::gen(&mut rng);
//         unsafe {
//             if let (Some(ref_sk), Some(ref_pk)) = (sk_ptr.as_mut(), pk_ptr.as_mut()) {
//                 *ref_sk = Box::into_raw(Box::new(sk));
//                 *ref_pk = Box::into_raw(Box::new(pk));
//                 return 0;
//             }
//             NULLPOINTERERR
//         }
//     }
//
//     #[no_mangle]
//     pub extern "C" fn msp_sign(
//         msg_ptr: *const c_char,
//         key_ptr: MspSkPtr,
//         signature_pts: *mut MspSigPtr,
//     ) -> i64 {
//         unsafe {
//             if let (Some(ref_key), Some(ref_msg), Some(ref_sig)) =
//             (key_ptr.as_ref(), msg_ptr.as_ref(), signature_pts.as_mut())
//             {
//                 let msg = CStr::from_ptr(ref_msg);
//                 *ref_sig = Box::into_raw(Box::new(Msp::sign(ref_key, msg.to_bytes())));
//                 return 0;
//             }
//             NULLPOINTERERR
//         }
//     }
//
//     #[no_mangle]
//     pub extern "C" fn msp_verify(
//         msg_ptr: *const c_char,
//         key_ptr: MspMvkPtr,
//         sig_ptr: MspSigPtr,
//     ) -> i64 {
//         unsafe {
//             if let (Some(ref_msg), Some(ref_key), Some(ref_sig)) =
//             (msg_ptr.as_ref(), key_ptr.as_ref(), sig_ptr.as_ref())
//             {
//                 let msg = CStr::from_ptr(ref_msg);
//                 return match Msp::ver(msg.to_bytes(), ref_key, ref_sig) {
//                     Ok(_) => 0,
//                     Err(_) => -1,
//                 };
//             }
//             NULLPOINTERERR
//         }
//     }
// }
// mod atms {
//     use super::*;
//     use crate::atms::Stake;
//     use crate::error::AtmsError;
//     use core::slice;
//
//     #[no_mangle]
//     /// Performs the key registration. Returns 0 upon success, or -1 if one of the keys included in
//     /// the registration have an invalid proof of possession.
//     pub extern "C" fn avk_key_registration(
//         keys: *const MspPkPtr,
//         stake: *const Stake,
//         nr_signers: usize,
//         threshold: usize,
//         avk_key: *mut AtmsRegistrationPtr,
//     ) -> i64 {
//         unsafe {
//             if let (Some(ref_key), Some(ref_stake), Some(ref_avk_key)) =
//             (keys.as_ref(), stake.as_ref(), avk_key.as_mut())
//             {
//                 let stake = slice::from_raw_parts(ref_stake, nr_signers);
//                 let pks = slice::from_raw_parts(ref_key, nr_signers)
//                     .iter()
//                     .zip(stake.iter())
//                     .map(|(p, s)| (**p, *s))
//                     .collect::<Vec<_>>();
//                 return match AtmsRegistration::new(&pks, threshold as u64) {
//                     Ok(k) => {
//                         *ref_avk_key = Box::into_raw(Box::new(k));
//                         0
//                     }
//                     Err(_) => -1,
//                 };
//             }
//             NULLPOINTERERR
//         }
//     }
//
//     #[no_mangle]
//     pub extern "C" fn atms_registration_to_avk(
//         avk_ptr: *mut AvkPtr,
//         registration_ptr: AtmsRegistrationPtr,
//     ) -> i64 {
//         unsafe {
//             if let (Some(ref_avk), Some(ref_registration)) =
//             (avk_ptr.as_mut(), registration_ptr.as_ref())
//             {
//                 *ref_avk = Box::into_raw(Box::new(ref_registration.to_avk()));
//                 return 0;
//             }
//             NULLPOINTERERR
//         }
//     }
//
//     #[no_mangle]
//     pub extern "C" fn atms_aggregate_sigs(
//         sigs_ptr: *const MspSigPtr,
//         pks_ptr: *const MspMvkPtr,
//         avk_ptr: AtmsRegistrationPtr,
//         nr_signatures: usize,
//         aggr_sig: *mut AsigPtr,
//     ) -> i64 {
//         unsafe {
//             if let (Some(ref_sigs), Some(ref_pks), Some(ref_avk), Some(ref_aggr_sig)) = (
//                 sigs_ptr.as_ref(),
//                 pks_ptr.as_ref(),
//                 avk_ptr.as_ref(),
//                 aggr_sig.as_mut(),
//             ) {
//                 let sigs = slice::from_raw_parts(ref_sigs, nr_signatures)
//                     .iter()
//                     .zip(slice::from_raw_parts(ref_pks, nr_signatures).iter())
//                     .map(|(p, k)| ((**k), **p))
//                     .collect::<Vec<_>>();
//                 *ref_aggr_sig = Box::into_raw(Box::new(Asig::new::<H>(ref_avk, &sigs)));
//                 return 0;
//             }
//             NULLPOINTERERR
//         }
//     }
//
//     #[no_mangle]
//     /// Verifies a signature `sig_ptr` under aggregated key `avk_ptr`. Returns:
//     /// * 0 upon success
//     /// * -1 if the threshold is not reached
//     /// * -2 if there were duplicates keys in `self`
//     /// * -3 if there is an invalid proof of Merkle Tree membership
//     /// * -4 if a key in `self` is not found in `avk_ptr`
//     /// * -5 if the signature is invalid
//     pub extern "C" fn atms_verify_sig(
//         msg_ptr: *const c_char,
//         sig_ptr: AsigPtr,
//         avk_ptr: AvkPtr,
//         threshold: Stake,
//     ) -> i64 {
//         unsafe {
//             if let (Some(ref_msg), Some(ref_sig), Some(ref_avk)) =
//             (msg_ptr.as_ref(), sig_ptr.as_ref(), avk_ptr.as_ref())
//             {
//                 let msg = CStr::from_ptr(ref_msg);
//                 return match ref_sig.verify::<H>(msg.to_bytes(), ref_avk, threshold) {
//                     Ok(_) => 0,
//                     Err(AtmsError::TooMuchOutstandingStake(_)) => -1,
//                     Err(AtmsError::FoundDuplicates(_)) => -2,
//                     Err(AtmsError::InvalidMerkleProof(_)) => -3,
//                     Err(AtmsError::InvalidSignature) => -4,
//                     _ => {
//                         panic!("All errors than can happen from sig.verify are covered");
//                     }
//                 };
//             }
//             NULLPOINTERERR
//         }
//     }
// }
