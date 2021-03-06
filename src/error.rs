//! Errors specific to this crate

use crate::multi_sig::PublicKey;
use blst::BLST_ERROR;

#[derive(Debug, thiserror::Error, Eq, PartialEq)]
/// Errors associated with Atms
pub enum AtmsError {
    /// This error occurs when one tries to register an existing key
    #[error("Cannot register existing key.")]
    RegisterExistingKey(PublicKey),
    /// The proof that a batch of `PK`s are members of the MerkleTree is false
    #[error("Proof of Merkle Tree membership is invalid.")]
    InvalidMerkleProof,
    /// A key submitted for aggregation is invalid.
    #[error("Invalid key provided in the set of keys.")]
    InvalidKey,
    /// A key submitted contains an invalid PoP.
    #[error("Key with invalid PoP provided in the set of keys.")]
    InvalidPoP,
    /// This error occurs when we try to aggregate a signature from a participant
    /// that is not registered
    #[error("Trying to aggregate key from non-registered participant")]
    NonRegisteredParticipant,
    /// Duplicate non-signers in signature
    #[error("Submitted keys of non-signers contains duplicates.")]
    FoundDuplicates(PublicKey),
    /// Non-signers sum to the given stake, which is more than half of total
    #[error("Signatures do not exceed the required threshold {0}.")]
    TooMuchOutstandingSigners(usize),
    /// Underlying signature scheme failed to verify
    #[error("Invalid Signature.")]
    InvalidSignature,
    /// The given public key does not correspond to the aggregation of the given
    /// set of keys
    #[error("Given public key does not correspond to the aggregation of the set of public keys.")]
    InvalidAggregation,
    /// This error occurs when the the serialization of the raw bytes failed
    #[error("Invalid signature")]
    SerializationError,
    /// This error occurs when the underlying function is passed infinity or an element outsize of the group
    #[error("Unexpected point.")]
    UnexpectedBlstTypes,
}

pub(crate) fn blst_err_to_atms(e: BLST_ERROR) -> Result<(), AtmsError> {
    match e {
        BLST_ERROR::BLST_SUCCESS => Ok(()),
        BLST_ERROR::BLST_VERIFY_FAIL => Err(AtmsError::InvalidSignature),
        BLST_ERROR::BLST_AGGR_TYPE_MISMATCH => Err(AtmsError::UnexpectedBlstTypes),
        BLST_ERROR::BLST_PK_IS_INFINITY => Err(AtmsError::UnexpectedBlstTypes),
        _ => Err(AtmsError::SerializationError),
    }
}

#[derive(Debug, thiserror::Error)]
pub enum MerkleTreeError {
    /// This error occurs when the claimed path is invalid.
    #[error("Invalid merkle path")]
    InvalidPath,
    /// This error occurs when the bytes provided to convert into a merkle tree
    /// have invalid size.
    #[error("Invalid sized bytes.")]
    InvalidSizedBytes,
    /// This error occures when the index of a proved element is out of bounds
    #[error("Index out of bounds")]
    IndexOutOfBounds,
}

impl From<MerkleTreeError> for AtmsError {
    fn from(e: MerkleTreeError) -> Self {
        match e {
            MerkleTreeError::InvalidPath => AtmsError::InvalidMerkleProof,
            _ => AtmsError::SerializationError,
        }
    }
}
