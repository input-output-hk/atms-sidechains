#![warn(missing_docs, rust_2018_idioms)]
//! ATMS

mod atms;
mod error;
mod merkle_tree;

pub use crate::{
    atms::{AtmsPublicKey, AtmsPrivateKey, AtmsSignature, AtmsPoP, AtmsAggregateSig},
    merkle_tree::MerkleTree,
};

#[test]
fn hallo() {
    assert!(true);
}