#![cfg_attr(not(feature = "std"), no_std)]
#![doc = include_str!("../README.md")]
use cfg_if::cfg_if;

cfg_if! {
    if #[cfg(feature = "std")] {
        pub mod batch;

        mod domain;
        mod error;
        mod hash;
        mod signature;
        mod signing_key;
        mod verification_key;

        use hash::HStar;

        pub use domain::{Binding, Domain, SpendAuth};
        pub use error::Error;
        pub use signature::Signature;
        pub use signing_key::SigningKey;
        pub use verification_key::{VerificationKey, VerificationKeyBytes};

        pub use decaf377::Fr;
    } else {
    }
}
