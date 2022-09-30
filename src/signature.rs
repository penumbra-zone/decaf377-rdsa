use std::convert::TryFrom;
use std::marker::PhantomData;

use crate::{Binding, Domain, Error, SpendAuth};

/// A `decaf377-rdsa` signature.
#[derive(Copy, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Signature<D: Domain> {
    pub(crate) r_bytes: [u8; 32],
    pub(crate) s_bytes: [u8; 32],
    pub(crate) _marker: PhantomData<D>,
}

impl<D: Domain> Signature<D> {
    /// Returns the bytes of the signature.
    ///
    /// This is the same as `.into()`, but does not require type inference.
    pub fn to_bytes(&self) -> [u8; 64] {
        let mut bytes = [0; 64];
        bytes[0..32].copy_from_slice(&self.r_bytes[..]);
        bytes[32..64].copy_from_slice(&self.s_bytes[..]);
        bytes
    }
}

impl std::fmt::Debug for Signature<Binding> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("Signature<Binding>")
            .field(&hex::encode(&<[u8; 64]>::from(*self)))
            .finish()
    }
}

impl std::fmt::Debug for Signature<SpendAuth> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("Signature<SpendAuth>")
            .field(&hex::encode(&<[u8; 64]>::from(*self)))
            .finish()
    }
}

impl<D: Domain> From<[u8; 64]> for Signature<D> {
    fn from(bytes: [u8; 64]) -> Signature<D> {
        let mut r_bytes = [0; 32];
        r_bytes.copy_from_slice(&bytes[0..32]);
        let mut s_bytes = [0; 32];
        s_bytes.copy_from_slice(&bytes[32..64]);
        Signature {
            r_bytes,
            s_bytes,
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

impl<D: Domain> std::cmp::PartialEq for Signature<D> {
    fn eq(&self, other: &Self) -> bool {
        self.r_bytes.eq(&other.r_bytes) && self.s_bytes.eq(&other.s_bytes)
    }
}

impl<D: Domain> std::cmp::Eq for Signature<D> {}
