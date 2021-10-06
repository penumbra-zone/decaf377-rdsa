#![doc = include_str!("../README.md")]

pub mod batch;
mod domain;
mod error;
mod hash;
mod signature;
mod signing_key;
mod verification_key;

/// An element of the JubJub scalar field used for randomization of public and secret keys.
pub type Randomizer = decaf377::Fr;

use hash::HStar;

pub use domain::{Binding, Domain, SpendAuth};
pub use error::Error;
pub use signature::Signature;
pub use signing_key::SigningKey;
pub use verification_key::{VerificationKey, VerificationKeyBytes};
