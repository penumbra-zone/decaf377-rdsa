use ark_ff::{Field as _, One, UniformRand, Zero};

pub use frost_core::{frost, Ciphersuite, Field, FieldError, Group, GroupError};

use rand_core;

use decaf377::{Element, FieldExt, Fr};

use crate::{hash::HStar, SpendAuth};

#[derive(Copy, Clone)]
pub struct Decaf377ScalarField;

impl Field for Decaf377ScalarField {
    type Scalar = Fr;

    type Serialization = [u8; 32];

    fn zero() -> Self::Scalar {
        Fr::zero()
    }

    fn one() -> Self::Scalar {
        Fr::one()
    }

    fn invert(scalar: &Self::Scalar) -> Result<Self::Scalar, FieldError> {
        scalar.inverse().ok_or(FieldError::InvalidZeroScalar)
    }

    fn random<R: rand_core::RngCore + rand_core::CryptoRng>(rng: &mut R) -> Self::Scalar {
        Fr::rand(rng)
    }

    fn serialize(scalar: &Self::Scalar) -> Self::Serialization {
        scalar.to_bytes()
    }

    fn little_endian_serialize(scalar: &Self::Scalar) -> Self::Serialization {
        scalar.to_bytes()
    }

    fn deserialize(buf: &Self::Serialization) -> Result<Self::Scalar, FieldError> {
        Fr::from_bytes(*buf).map_err(|_| FieldError::MalformedScalar)
    }
}

#[derive(Copy, Clone, PartialEq, Eq)]
pub struct Decaf377Group;

impl Group for Decaf377Group {
    type Field = Decaf377ScalarField;

    type Element = Element;

    type Serialization = [u8; 32];

    fn cofactor() -> <Self::Field as Field>::Scalar {
        Fr::one()
    }

    fn identity() -> Self::Element {
        Element::default()
    }

    fn generator() -> Self::Element {
        decaf377::basepoint()
    }

    fn serialize(element: &Self::Element) -> Self::Serialization {
        element.vartime_compress().0
    }

    fn deserialize(buf: &Self::Serialization) -> Result<Self::Element, GroupError> {
        decaf377::Encoding(*buf)
            .vartime_decompress()
            .map_err(|_| GroupError::MalformedElement)
    }
}

#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub struct Decaf377Rdsa;

const CONTEXT_STRING: &str = "FROST-decaf377-rdsa-v1";

#[allow(non_snake_case)]
impl Ciphersuite for Decaf377Rdsa {
    const ID: &'static str = CONTEXT_STRING;

    type Group = Decaf377Group;

    type HashOutput = [u8; 32];

    type SignatureSerialization = crate::Signature<SpendAuth>;

    fn H1(m: &[u8]) -> <<Self::Group as Group>::Field as Field>::Scalar {
        HStar::default()
            .update(CONTEXT_STRING.as_bytes())
            .update(b"rho")
            .update(m)
            .finalize()
    }

    fn H2(m: &[u8]) -> <<Self::Group as Group>::Field as Field>::Scalar {
        HStar::default().update(m).finalize()
    }

    fn H3(m: &[u8]) -> <<Self::Group as Group>::Field as Field>::Scalar {
        HStar::default()
            .update(CONTEXT_STRING.as_bytes())
            .update(b"nonce")
            .update(m)
            .finalize()
    }

    fn H4(m: &[u8]) -> Self::HashOutput {
        // TODO: dont
        HStar::default()
            .update(CONTEXT_STRING.as_bytes())
            .update(b"msg")
            .update(m)
            .finalize()
            .to_bytes()
    }

    fn H5(m: &[u8]) -> Self::HashOutput {
        // TODO: dont
        HStar::default()
            .update(CONTEXT_STRING.as_bytes())
            .update(b"com")
            .update(m)
            .finalize()
            .to_bytes()
    }

    fn HDKG(m: &[u8]) -> Option<<<Self::Group as Group>::Field as Field>::Scalar> {
        Some(
            HStar::default()
                .update(CONTEXT_STRING.as_bytes())
                .update(b"dkg")
                .update(m)
                .finalize(),
        )
    }

    fn HID(m: &[u8]) -> Option<<<Self::Group as Group>::Field as Field>::Scalar> {
        Some(
            HStar::default()
                .update(CONTEXT_STRING.as_bytes())
                .update(b"id")
                .update(m)
                .finalize(),
        )
    }
}
