#![warn(missing_docs, rust_2018_idioms)]
//! ATMS

mod atms;
mod error;
mod merkle_tree;

pub use crate::{
    atms::{
        AggregateSig, ProofOfPossession, PublicKey, PublicKeyPoP, Registration, Signature,
        SigningKey,
    },
    error::AtmsError,
    merkle_tree::MerkleTree,
};
