//! C api. All functions return an i64, with 0 upon success, and -99 if the returned pointer
//! is null. Other error codes are function dependent.
use crate::{
    aggregation::{AggregateSig, Registration},
    error::AtmsError,
    multi_sig::{PublicKey, PublicKeyPoP, Signature, SigningKey},
};
use rand_core::OsRng;
use std::{ffi::CStr, os::raw::c_char};

pub const NULLPOINTERERR: i64 = -99;

type H = blake2::Blake2b;
type SigningKeyPtr = *mut SigningKey;
type PublicKeyPoPPtr = *mut PublicKeyPoP;
type PublicKeyPtr = *mut PublicKey;
type SignaturePtr = *mut Signature;
type RegistrationPtr = *mut Registration<H>;
type AggregateSigPtr = *mut AggregateSig<H>;
type AvkPtr = *mut Avk<H>;

/// Frees a signature pointer
macro_rules! free_pointer {
    ($type_name:ident, $pointer_type:ty) => {
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
    };
}

free_pointer!(signature, SignaturePtr);
free_pointer!(sk, SigningKeyPtr);
free_pointer!(pk, PublicKeyPtr);
free_pointer!(pkpop, PublicKeyPoPPtr);
free_pointer!(registration, RegistrationPtr);
free_pointer!(aggr_sig, AggregateSigPtr);
free_pointer!(avk, AvkPtr);

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
atms_serialisation!(aggr_sig, AggregateSigPtr, AggregateSig);
atms_serialisation!(avk, AvkPtr, Avk);

use crate::aggregation::Avk;

#[no_mangle]
pub extern "C" fn atms_generate_keypair(
    sk_ptr: *mut SigningKeyPtr,
    pk_ptr: *mut PublicKeyPoPPtr,
) -> i64 {
    let mut rng = OsRng::default();
    let sk = SigningKey::gen(&mut rng);
    let pk = PublicKeyPoP::from(&sk);
    unsafe {
        if let (Some(ref_sk), Some(ref_pk)) = (sk_ptr.as_mut(), pk_ptr.as_mut()) {
            *ref_sk = Box::into_raw(Box::new(sk));
            *ref_pk = Box::into_raw(Box::new(pk));
            return 0;
        }
        NULLPOINTERERR
    }
}

#[no_mangle]
pub extern "C" fn atms_pkpop_to_pk(pkpop_ptr: PublicKeyPoPPtr, pk_ptr: *mut PublicKeyPtr) -> i64 {
    unsafe {
        if let (Some(ref_pkpop), Some(ref_pk)) = (pkpop_ptr.as_ref(), pk_ptr.as_mut()) {
            match ref_pkpop.verify() {
                Ok(_) => {
                    *ref_pk = Box::into_raw(Box::new(ref_pkpop.0));
                }
                Err(_) => return -1,
            }
            return 0;
        }
        NULLPOINTERERR
    }
}

#[no_mangle]
pub extern "C" fn atms_sign(
    msg_ptr: *const c_char,
    key_ptr: SigningKeyPtr,
    signature_ptr: *mut SignaturePtr,
) -> i64 {
    unsafe {
        if let (Some(ref_key), Some(ref_msg), Some(ref_sig)) =
            (key_ptr.as_ref(), msg_ptr.as_ref(), signature_ptr.as_mut())
        {
            let msg = CStr::from_ptr(ref_msg);
            *ref_sig = Box::into_raw(Box::new(ref_key.sign(msg.to_bytes())));
            return 0;
        }
        NULLPOINTERERR
    }
}

#[no_mangle]
pub extern "C" fn atms_verify(
    msg_ptr: *const c_char,
    key_ptr: PublicKeyPtr,
    sig_ptr: SignaturePtr,
) -> i64 {
    unsafe {
        if let (Some(ref_msg), Some(ref_key), Some(ref_sig)) =
            (msg_ptr.as_ref(), key_ptr.as_ref(), sig_ptr.as_ref())
        {
            let msg = CStr::from_ptr(ref_msg);
            return match ref_sig.verify(ref_key, msg.to_bytes()) {
                Ok(_) => 0,
                Err(_) => -1,
            };
        }
        NULLPOINTERERR
    }
}

#[no_mangle]
/// Performs the key registration. Returns 0 upon success, or -1 if one of the keys included in
/// the registration have an invalid proof of possession.
pub extern "C" fn avk_key_registration(
    keys: *const PublicKeyPoPPtr,
    nr_signers: usize,
    avk_key: *mut RegistrationPtr,
) -> i64 {
    unsafe {
        if let (Some(ref_key), Some(ref_avk_key)) = (keys.as_ref(), avk_key.as_mut()) {
            let pks = slice::from_raw_parts(ref_key, nr_signers)
                .iter()
                .map(|p| **p)
                .collect::<Vec<_>>();
            return match Registration::new(&pks) {
                Ok(k) => {
                    *ref_avk_key = Box::into_raw(Box::new(k));
                    0
                }
                Err(_) => -1,
            };
        }
        NULLPOINTERERR
    }
}

#[no_mangle]
pub extern "C" fn atms_registration_to_avk(
    avk_ptr: *mut AvkPtr,
    registration_ptr: RegistrationPtr,
) -> i64 {
    unsafe {
        if let (Some(ref_avk), Some(ref_registration)) =
            (avk_ptr.as_mut(), registration_ptr.as_ref())
        {
            *ref_avk = Box::into_raw(Box::new(ref_registration.to_avk()));
            return 0;
        }
        NULLPOINTERERR
    }
}

#[no_mangle]
/// It aggregate the signatures submitted. For every signature submitted, this function
/// automatically inclues one copy of the signature per position in the merkle tree.
pub extern "C" fn atms_aggregate_sigs(
    msg_ptr: *const c_char,
    sigs_ptr: *const SignaturePtr,
    pks_ptr: *const PublicKeyPtr,
    reg_ptr: RegistrationPtr,
    nr_signatures: usize,
    aggr_sig: *mut AggregateSigPtr,
) -> i64 {
    unsafe {
        if let (Some(ref_msg), Some(ref_sigs), Some(ref_pks), Some(ref_reg), Some(ref_aggr_sig)) = (
            msg_ptr.as_ref(),
            sigs_ptr.as_ref(),
            pks_ptr.as_ref(),
            reg_ptr.as_ref(),
            aggr_sig.as_mut(),
        ) {
            let msg = CStr::from_ptr(ref_msg);
            let mut sigs = Vec::new();

            for (p, k) in slice::from_raw_parts(ref_sigs, nr_signatures)
                .iter()
                .zip(slice::from_raw_parts(ref_pks, nr_signatures).iter())
            {
                let indices = ref_reg.get_index(&**k);
                for index in indices {
                    sigs.push((index, **p));
                }
            }

            match AggregateSig::new(ref_reg, &sigs, msg.to_bytes()) {
                Ok(sig) => *ref_aggr_sig = Box::into_raw(Box::new(sig)),
                Err(AtmsError::NonRegisteredParticipant) => return -1,
                Err(AtmsError::InvalidSignature) => return -2,
                Err(AtmsError::UnexpectedBlstTypes) => return -3,
                Err(AtmsError::SerializationError) => return -4,
                Err(_) => unreachable!("No other erros should happen when aggregating signatures."),
            }

            return 0;
        }
        NULLPOINTERERR
    }
}

#[no_mangle]
/// Verifies a signature `sig_ptr` under aggregated key `avk_ptr`. Returns:
/// * 0 upon success
/// * -1 if the threshold is not reached
/// * -2 if there were duplicates keys in `self`
/// * -3 if there is an invalid proof of Merkle Tree membership
/// * -4 if a key in `self` is not found in `avk_ptr`
/// * -5 if the signature is invalid
pub extern "C" fn atms_verify_aggr(
    msg_ptr: *const c_char,
    sig_ptr: AggregateSigPtr,
    avk_ptr: AvkPtr,
    threshold: usize,
) -> i64 {
    unsafe {
        if let (Some(ref_msg), Some(ref_sig), Some(ref_avk)) =
            (msg_ptr.as_ref(), sig_ptr.as_ref(), avk_ptr.as_ref())
        {
            let msg = CStr::from_ptr(ref_msg);
            return match ref_sig.verify(msg.to_bytes(), ref_avk, threshold) {
                Ok(_) => 0,
                Err(AtmsError::TooMuchOutstandingSigners(_)) => -1,
                Err(AtmsError::FoundDuplicates(_)) => -2,
                Err(AtmsError::InvalidMerkleProof) => -3,
                Err(AtmsError::InvalidSignature) => -4,
                Err(AtmsError::UnexpectedBlstTypes) => -5,
                Err(AtmsError::SerializationError) => -6,
                _ => {
                    unreachable!("All errors than can happen from sig.verify are covered");
                }
            };
        }
        NULLPOINTERERR
    }
}
