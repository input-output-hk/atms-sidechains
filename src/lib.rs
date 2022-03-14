#![warn(missing_docs, rust_2018_idioms)]
//! ATMS

mod aggregation;
mod c_api;
mod error;
mod merkle_tree;
mod multi_sig;

pub use crate::{
    aggregation::{AggregateSig, Registration},
    error::AtmsError,
    merkle_tree::{MerkleTree, Path},
    multi_sig::{ProofOfPossession, PublicKey, PublicKeyPoP, Signature, SigningKey},
};
