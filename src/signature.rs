use core::{cmp, convert::TryFrom, marker::PhantomData};

use crate::{Domain, Error};

/// A `decaf377-rdsa` signature.
#[derive(Copy, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(try_from = "&[u8]", into = "Vec<u8>"))]
pub struct Signature<D: Domain> {
    bytes: [u8; 64],
    _marker: PhantomData<D>,
}

impl<D: Domain> AsRef<[u8]> for Signature<D> {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

impl<D: Domain> Signature<D> {
    /// Returns the bytes of the signature.
    ///
    /// This is the same as `.into()`, but does not require type inference.
    pub fn to_bytes(&self) -> [u8; 64] {
        self.bytes
    }

    pub(crate) fn from_parts(r_bytes: [u8; 32], s_bytes: [u8; 32]) -> Self {
        let mut bytes = [0; 64];
        bytes[0..32].copy_from_slice(&r_bytes[..]);
        bytes[32..64].copy_from_slice(&s_bytes[..]);
        Self {
            bytes,
            _marker: PhantomData,
        }
    }

    pub(crate) fn r_bytes(&self) -> [u8; 32] {
        self.bytes[0..32].try_into().expect("32 byte array")
    }

    pub(crate) fn s_bytes(&self) -> [u8; 32] {
        self.bytes[32..64].try_into().expect("32 byte array")
    }
}

impl<D: Domain> From<[u8; 64]> for Signature<D> {
    fn from(bytes: [u8; 64]) -> Signature<D> {
        Signature {
            bytes,
            _marker: PhantomData,
        }
    }
}

impl<D: Domain> From<Signature<D>> for [u8; 64] {
    fn from(sig: Signature<D>) -> [u8; 64] {
        sig.to_bytes()
    }
}

impl<D: Domain> TryFrom<&[u8]> for Signature<D> {
    type Error = Error;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        if bytes.len() == 64 {
            let mut bytes64 = [0u8; 64];
            bytes64.copy_from_slice(bytes);
            Ok(bytes64.into())
        } else {
            Err(Error::WrongSliceLength {
                expected: 64,
                found: bytes.len(),
            })
        }
    }
}

impl<D: Domain> cmp::PartialEq for Signature<D> {
    fn eq(&self, other: &Self) -> bool {
        self.bytes == other.bytes
    }
}

impl<D: Domain> cmp::Eq for Signature<D> {}

#[cfg(feature = "std")]
mod std_only {
    use super::*;
    use std::fmt;

    use crate::{Binding, Signature, SpendAuth};

    impl<D: Domain> TryFrom<Vec<u8>> for Signature<D> {
        type Error = Error;

        fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
            value.as_slice().try_into()
        }
    }

    impl<D: Domain> From<Signature<D>> for Vec<u8> {
        fn from(sig: Signature<D>) -> Vec<u8> {
            sig.to_bytes().into()
        }
    }

    impl fmt::Debug for Signature<Binding> {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_tuple("Signature<Binding>")
                .field(&hex::encode(&<[u8; 64]>::from(*self)))
                .finish()
        }
    }

    impl fmt::Debug for Signature<SpendAuth> {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_tuple("Signature<SpendAuth>")
                .field(&hex::encode(&<[u8; 64]>::from(*self)))
                .finish()
        }
    }
}

#[cfg(feature = "std")]
pub use std_only::*;
