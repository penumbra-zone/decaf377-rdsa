/// Abstracts over different signature domains.
///
/// This design is described [at the end of §5.4.6][concretereddsa] of the Zcash
/// protocol specification: the generator used for the signature scheme is left
/// as an unspecified parameter, chosen differently for each signature domain.
///
/// To handle this, we encode the domain as a type parameter.
///
/// [concretereddsa]: https://zips.z.cash/protocol/protocol.pdf#concretereddsa
pub trait Domain: private::Sealed {}

/// A type variable corresponding to Zcash's `BindingSig`.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Binding {}
impl Domain for Binding {}

/// A type variable corresponding to Zcash's `SpendAuthSig`.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum SpendAuth {}
impl Domain for SpendAuth {}

pub(crate) mod private {
    use super::*;

    use ark_ff::PrimeField;

    fn hash_to_group(input: &[u8]) -> decaf377::Element {
        decaf377::Element::map_to_group_cdh(&decaf377::Fq::from_le_bytes_mod_order(
            blake2b_simd::blake2b(input).as_bytes(),
        ))
    }

    pub trait Sealed: Copy + Clone + Eq + PartialEq + std::fmt::Debug {
        fn basepoint() -> decaf377::Element;
    }
    impl Sealed for Binding {
        fn basepoint() -> decaf377::Element {
            hash_to_group(b"decaf377-rdsa-binding")
        }
    }
    impl Sealed for SpendAuth {
        fn basepoint() -> decaf377::Element {
            decaf377::basepoint()
        }
    }
}

pub(crate) use private::Sealed;
