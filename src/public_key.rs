use std::{convert::TryFrom, marker::PhantomData};

use crate::{Binding, Error, Randomizer, SigType, Signature, SpendAuth};

/// A refinement type indicating that the inner `[u8; 32]` represents an
/// encoding of a RedJubJub public key.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct PublicKeyBytes<T: SigType> {
    bytes: [u8; 32],
    _marker: PhantomData<T>,
}

impl<T: SigType> From<[u8; 32]> for PublicKeyBytes<T> {
    fn from(bytes: [u8; 32]) -> PublicKeyBytes<T> {
        PublicKeyBytes {
            bytes,
            _marker: PhantomData,
        }
    }
}

impl<T: SigType> From<PublicKeyBytes<T>> for [u8; 32] {
    fn from(refined: PublicKeyBytes<T>) -> [u8; 32] {
        refined.bytes
    }
}

/// A RedJubJub public key.
// XXX PartialEq, Eq?
#[derive(Copy, Clone, Debug)]
pub struct PublicKey<T: SigType> {
    // XXX-jubjub: this should just be Point
    pub(crate) point: jubjub::ExtendedPoint,
    // XXX should this just store a PublicKeyBytes?
    pub(crate) bytes: [u8; 32],
    pub(crate) _marker: PhantomData<T>,
}

impl<T: SigType> From<PublicKey<T>> for PublicKeyBytes<T> {
    fn from(pk: PublicKey<T>) -> PublicKeyBytes<T> {
        let PublicKey { bytes, _marker, .. } = pk;
        PublicKeyBytes { bytes, _marker }
    }
}

impl<T: SigType> TryFrom<PublicKeyBytes<T>> for PublicKey<T> {
    type Error = Error;

    fn try_from(bytes: PublicKeyBytes<T>) -> Result<Self, Self::Error> {
        // XXX-jubjub: this should not use CtOption
        // XXX-jubjub: this takes ownership of bytes, while Fr doesn't.
        let maybe_point = jubjub::AffinePoint::from_bytes(bytes.bytes);
        if maybe_point.is_some().into() {
            Ok(PublicKey {
                point: maybe_point.unwrap().into(),
                bytes: bytes.bytes,
                _marker: PhantomData,
            })
        } else {
            Err(Error::MalformedPublicKey)
        }
    }
}

impl<T: SigType> PublicKey<T> {
    /// Randomize this public key with the given `randomizer`.
    pub fn randomize(&self, randomizer: Randomizer) -> PublicKey<T> {
        unimplemented!();
    }
}

impl PublicKey<Binding> {
    /// Verify a Zcash `BindingSig` over `msg` made by this public key.
    // This is similar to impl signature::Verifier but without boxed errors
    pub fn verify(&self, msg: &[u8], signature: &Signature<Binding>) -> Result<(), Error> {
        // this lets us specialize the basepoint parameter, could call a verify_inner
        unimplemented!();
    }
}

impl PublicKey<SpendAuth> {
    /// Verify a Zcash `SpendAuthSig` over `msg` made by this public key.
    // This is similar to impl signature::Verifier but without boxed errors
    pub fn verify(&self, msg: &[u8], signature: &Signature<SpendAuth>) -> Result<(), Error> {
        // this lets us specialize the basepoint parameter, could call a verify_inner
        unimplemented!();
    }
}