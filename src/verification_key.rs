use std::{
    convert::TryFrom,
    hash::{Hash, Hasher},
    marker::PhantomData,
};

use decaf377::{Fr, FrExt};

use crate::{domain::Sealed, Domain, Error, Randomizer, Signature, SpendAuth};

/// A refinement type for `[u8; 32]` indicating that the bytes represent
/// an encoding of a `decaf377-rdsa` verification key.
///
/// This is useful for representing a compressed verification key; the
/// [`VerificationKey`] type in this library holds other decompressed state
/// used in signature verification.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct VerificationKeyBytes<D: Domain> {
    pub(crate) bytes: [u8; 32],
    pub(crate) _marker: PhantomData<D>,
}

impl<D: Domain> From<[u8; 32]> for VerificationKeyBytes<D> {
    fn from(bytes: [u8; 32]) -> VerificationKeyBytes<D> {
        VerificationKeyBytes {
            bytes,
            _marker: PhantomData,
        }
    }
}

impl<D: Domain> From<VerificationKeyBytes<D>> for [u8; 32] {
    fn from(refined: VerificationKeyBytes<D>) -> [u8; 32] {
        refined.bytes
    }
}

impl<D: Domain> Hash for VerificationKeyBytes<D> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.bytes.hash(state);
        self._marker.hash(state);
    }
}

/// A valid `decaf377-rdsa` verification key.
///
/// This type holds decompressed state used in signature verification; if the
/// verification key may not be used immediately, it is probably better to use
/// [`VerificationKeyBytes`], which is a refinement type for `[u8; 32]`.
#[derive(Copy, Clone, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(try_from = "VerificationKeyBytes<D>"))]
#[cfg_attr(feature = "serde", serde(into = "VerificationKeyBytes<D>"))]
#[cfg_attr(feature = "serde", serde(bound = "D: Domain"))]
pub struct VerificationKey<D: Domain> {
    pub(crate) point: decaf377::Element,
    pub(crate) bytes: VerificationKeyBytes<D>,
}

impl<D: Domain> From<VerificationKey<D>> for VerificationKeyBytes<D> {
    fn from(pk: VerificationKey<D>) -> VerificationKeyBytes<D> {
        pk.bytes
    }
}

impl<D: Domain> From<VerificationKey<D>> for [u8; 32] {
    fn from(pk: VerificationKey<D>) -> [u8; 32] {
        pk.bytes.bytes
    }
}

impl<'a, D: Domain> From<&'a VerificationKey<D>> for [u8; 32] {
    fn from(pk: &'a VerificationKey<D>) -> [u8; 32] {
        pk.bytes.bytes
    }
}

impl<D: Domain> TryFrom<VerificationKeyBytes<D>> for VerificationKey<D> {
    type Error = Error;

    fn try_from(bytes: VerificationKeyBytes<D>) -> Result<Self, Self::Error> {
        // Note: the identity element is allowed as a verification key.
        let point = decaf377::Encoding(bytes.bytes)
            .decompress()
            .map_err(|_| Error::MalformedVerificationKey)?;

        Ok(VerificationKey { point, bytes })
    }
}

impl<D: Domain> TryFrom<[u8; 32]> for VerificationKey<D> {
    type Error = Error;

    fn try_from(bytes: [u8; 32]) -> Result<Self, Self::Error> {
        use std::convert::TryInto;
        VerificationKeyBytes::from(bytes).try_into()
    }
}

impl VerificationKey<SpendAuth> {
    /// Randomize this verification key with the given `randomizer`.
    ///
    /// Randomization is only supported for `SpendAuth` keys.
    pub fn randomize(&self, randomizer: &Randomizer) -> VerificationKey<SpendAuth> {
        let point = self.point + (SpendAuth::basepoint() * randomizer);
        let bytes = VerificationKeyBytes {
            bytes: point.compress().into(),
            _marker: PhantomData,
        };
        VerificationKey { bytes, point }
    }
}

impl<D: Domain> VerificationKey<D> {
    pub(crate) fn from(s: &Fr) -> VerificationKey<D> {
        let point = &D::basepoint() * s;
        let bytes = VerificationKeyBytes {
            bytes: point.compress().into(),
            _marker: PhantomData,
        };
        VerificationKey { bytes, point }
    }

    /// Verify a purported `signature` over `msg` made by this verification key.
    // This is similar to impl signature::Verifier but without boxed errors
    pub fn verify(&self, msg: &[u8], signature: &Signature<D>) -> Result<(), Error> {
        use crate::HStar;
        let c = HStar::default()
            .update(&signature.r_bytes[..])
            .update(&self.bytes.bytes[..]) // XXX ugly
            .update(msg)
            .finalize();
        self.verify_prehashed(signature, c)
    }

    /// Verify a purported `signature` with a prehashed challenge.
    #[allow(non_snake_case)]
    pub(crate) fn verify_prehashed(&self, signature: &Signature<D>, c: Fr) -> Result<(), Error> {
        let R = decaf377::Encoding(signature.r_bytes)
            .decompress()
            .map_err(|_| Error::InvalidSignature)?;

        let s = Fr::from_bytes(signature.s_bytes).map_err(|_| Error::InvalidSignature)?;

        // XXX rewrite as normal double scalar mul
        // Verify check is h * ( - s * B + R  + c * A) == 0
        //                 h * ( s * B - c * A - R) == 0
        let sB = D::basepoint() * s;
        let cA = self.point * c;
        let check = sB - cA - R;

        if check.is_identity() {
            Ok(())
        } else {
            Err(Error::InvalidSignature)
        }
    }
}
