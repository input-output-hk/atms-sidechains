#![warn(missing_docs, rust_2018_idioms)]
//! Ad-Hoc Threshold MultiSignatures (ATMS) implementation using
//! [Boldyreva](https://link.springer.com/chapter/10.1007%2F3-540-36288-6_3)
//! multi signature scheme as described in Section 5.2 of the
//! [Proof-of-Stake Sidechains](https://cointhinktank.com/upload/Proof-of-Stake%20Sidechains.pdf)
//! by Gazi, Kiayias and Zindros. Elliptic curve cryptography, and basic
//! signature procedures are performed using the [`blst`](https://github.com/supranational/blst)
//! library by supranational which implements BLS signatures over curve
//! BLS12-381.

extern crate core;

pub mod aggregation;
mod c_api;
mod error;
mod merkle_tree;
pub mod multi_sig;

pub use crate::{
    error::AtmsError,
    merkle_tree::{MerkleTree, MerkleTreeCommitment, Path},
};
