#![cfg_attr(not(feature = "std"), no_std)]
#![doc = include_str!("../README.md")]
use cfg_if::cfg_if;

mod domain;
mod error;
mod hash;
use hash::HStar;
mod signature;

pub use domain::{Binding, Domain, SpendAuth};
pub use error::Error;

cfg_if! {
    if #[cfg(feature = "std")] {
        pub mod batch;

        mod signing_key;
        mod verification_key;

        pub use signature::Signature;
        pub use signing_key::SigningKey;
        pub use verification_key::{VerificationKey, VerificationKeyBytes};

        pub use decaf377::Fr;
    }
}
