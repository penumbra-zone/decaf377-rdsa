use std::{
    cmp::Ord,
    convert::TryFrom,
    hash::{Hash, Hasher},
    marker::PhantomData,
};

use decaf377::{FieldExt, Fr};

use crate::{domain::Sealed, Binding, Domain, Error, Signature, SpendAuth};

/// A refinement type for `[u8; 32]` indicating that the bytes represent
/// an encoding of a `decaf377-rdsa` verification key.
///
/// This is useful for representing a compressed verification key; the
/// [`VerificationKey`] type in this library holds other decompressed state
/// used in signature verification.
#[derive(Copy, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct VerificationKeyBytes<D: Domain> {
    pub(crate) bytes: [u8; 32],
    pub(crate) _marker: PhantomData<D>,
}

impl<D: Domain> AsRef<[u8; 32]> for VerificationKeyBytes<D> {
    fn as_ref(&self) -> &[u8; 32] {
        &self.bytes
    }
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

impl<D: Domain> PartialOrd for VerificationKeyBytes<D> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        self.bytes.partial_cmp(&other.bytes)
    }
}

impl<D: Domain> Ord for VerificationKeyBytes<D> {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.bytes.cmp(&other.bytes)
    }
}

/// A valid `decaf377-rdsa` verification key.
///
/// This type holds decompressed state used in signature verification; if the
/// verification key may not be used immediately, it is probably better to use
/// [`VerificationKeyBytes`], which is a refinement type for `[u8; 32]`.
#[derive(Copy, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(try_from = "VerificationKeyBytes<D>"))]
#[cfg_attr(feature = "serde", serde(into = "VerificationKeyBytes<D>"))]
#[cfg_attr(feature = "serde", serde(bound = "D: Domain"))]
pub struct VerificationKey<D: Domain> {
    pub(crate) point: decaf377::Element,
    pub(crate) bytes: VerificationKeyBytes<D>,
}

impl<D: Domain> Hash for VerificationKey<D> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.bytes.hash(state);
    }
}

impl<D: Domain> PartialOrd for VerificationKey<D> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        self.bytes.partial_cmp(&other.bytes)
    }
}

impl<D: Domain> Ord for VerificationKey<D> {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.bytes.cmp(&other.bytes)
    }
}

impl<D: Domain> From<VerificationKey<D>> for VerificationKeyBytes<D> {
    fn from(pk: VerificationKey<D>) -> VerificationKeyBytes<D> {
        pk.bytes
    }
}

impl<D: Domain> VerificationKey<D> {
    /// Returns the byte encoding of the verification key.
    ///
    /// This is the same as `.into()`, but does not require type inference.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.bytes.bytes
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

impl<D: Domain> TryFrom<&[u8]> for VerificationKeyBytes<D> {
    type Error = Error;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        if bytes.len() == 32 {
            let mut bytes32 = [0u8; 32];
            bytes32.copy_from_slice(&bytes);
            Ok(bytes32.into())
        } else {
            Err(Error::WrongSliceLength {
                expected: 32,
                found: bytes.len(),
            })
        }
    }
}

impl<D: Domain> TryFrom<&[u8]> for VerificationKey<D> {
    type Error = Error;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        use std::convert::TryInto;
        VerificationKeyBytes::try_from(bytes)?.try_into()
    }
}

impl<D: Domain> AsRef<[u8; 32]> for VerificationKey<D> {
    fn as_ref(&self) -> &[u8; 32] {
        self.bytes.as_ref()
    }
}

impl VerificationKey<SpendAuth> {
    /// Randomize this verification key with the given `randomizer`.
    ///
    /// Randomization is only supported for `SpendAuth` keys.
    pub fn randomize(&self, randomizer: &Fr) -> VerificationKey<SpendAuth> {
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

    /// Convenience method for identity checks.
    pub fn is_identity(&self) -> bool {
        self.point.is_identity()
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

impl<D: Domain> std::cmp::PartialEq for VerificationKey<D> {
    fn eq(&self, other: &Self) -> bool {
        self.bytes.eq(&other.bytes)
    }
}

impl<D: Domain> std::cmp::PartialEq for VerificationKeyBytes<D> {
    fn eq(&self, other: &Self) -> bool {
        self.bytes.eq(&other.bytes)
    }
}

impl<D: Domain> std::cmp::Eq for VerificationKey<D> {}
impl<D: Domain> std::cmp::Eq for VerificationKeyBytes<D> {}

impl std::fmt::Debug for VerificationKey<Binding> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("VerificationKey<Binding>")
            .field(&hex::encode(&<[u8; 32]>::from(*self)))
            .finish()
    }
}

impl std::fmt::Debug for VerificationKey<SpendAuth> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("VerificationKey<SpendAuth>")
            .field(&hex::encode(&<[u8; 32]>::from(*self)))
            .finish()
    }
}

impl std::fmt::Debug for VerificationKeyBytes<Binding> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("VerificationKeyBytes<Binding>")
            .field(&hex::encode(&<[u8; 32]>::from(*self)))
            .finish()
    }
}

impl std::fmt::Debug for VerificationKeyBytes<SpendAuth> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("VerificationKeyBytes<SpendAuth>")
            .field(&hex::encode(&<[u8; 32]>::from(*self)))
            .finish()
    }
}
