use std::marker::PhantomData;

use crate::{Binding, Domain, SpendAuth};

/// A `decaf377-rdsa` signature.
#[derive(Copy, Clone, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Signature<D: Domain> {
    pub(crate) r_bytes: [u8; 32],
    pub(crate) s_bytes: [u8; 32],
    pub(crate) _marker: PhantomData<D>,
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
        let mut bytes = [0; 64];
        bytes[0..32].copy_from_slice(&sig.r_bytes[..]);
        bytes[32..64].copy_from_slice(&sig.s_bytes[..]);
        bytes
    }
}
