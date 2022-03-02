#![warn(missing_docs, rust_2018_idioms)]
//! ATMS

mod atms;
mod error;
mod merkle_tree;

pub use crate::{
    atms::{
        AggregateSig, PrivateKey, ProofOfPossession, PublicKey, PublicKeyPoP, Registration,
        Signature,
    },
    merkle_tree::MerkleTree,
};

#[test]
fn hallo() {
    assert!(true);
}
