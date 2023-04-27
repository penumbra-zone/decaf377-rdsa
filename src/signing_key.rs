use std::{
    convert::{TryFrom, TryInto},
    marker::PhantomData,
};

use ark_ff::PrimeField;
use decaf377::{FieldExt, Fr};
use rand_core::{CryptoRng, RngCore};

use crate::{Binding, Domain, Error, Signature, SpendAuth, VerificationKey};

/// A `decaf377-rdsa` signing key.
#[derive(Copy, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(try_from = "SerdeHelper"))]
#[cfg_attr(feature = "serde", serde(into = "SerdeHelper"))]
#[cfg_attr(feature = "serde", serde(bound = "D: Domain"))]
pub struct SigningKey<D: Domain> {
    sk: Fr,
    pk: VerificationKey<D>,
}

impl std::fmt::Debug for SigningKey<Binding> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("SigningKey<Binding>")
            .field(&hex::encode(&<[u8; 32]>::from(*self)))
            .finish()
    }
}

impl std::fmt::Debug for SigningKey<SpendAuth> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("SigningKey<SpendAuth>")
            .field(&hex::encode(&<[u8; 32]>::from(*self)))
            .finish()
    }
}

impl<'a, D: Domain> From<&'a SigningKey<D>> for VerificationKey<D> {
    fn from(sk: &'a SigningKey<D>) -> VerificationKey<D> {
        sk.pk.clone()
    }
}

impl<'a, D: Domain> From<SigningKey<D>> for VerificationKey<D> {
    fn from(sk: SigningKey<D>) -> VerificationKey<D> {
        sk.pk.clone()
    }
}

impl<D: Domain> From<SigningKey<D>> for [u8; 32] {
    fn from(sk: SigningKey<D>) -> [u8; 32] {
        sk.sk.to_bytes()
    }
}

impl<D: Domain> SigningKey<D> {
    /// Returns the byte encoding of the signing key.
    ///
    /// This is the same as `.into()`, but does not require type inference.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.sk.to_bytes()
    }
}

impl<D: Domain> TryFrom<[u8; 32]> for SigningKey<D> {
    type Error = Error;

    fn try_from(bytes: [u8; 32]) -> Result<Self, Self::Error> {
        use ark_serialize::CanonicalDeserialize;
        let sk = Fr::deserialize_compressed(&bytes[..]).map_err(|_| Error::MalformedSigningKey)?;
        Ok(Self::new_from_field(sk))
    }
}

impl<D: Domain> TryFrom<&[u8]> for SigningKey<D> {
    type Error = Error;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        if bytes.len() == 32 {
            let mut bytes32 = [0u8; 32];
            bytes32.copy_from_slice(bytes);
            bytes32.try_into()
        } else {
            Err(Error::WrongSliceLength {
                expected: 32,
                found: bytes.len(),
            })
        }
    }
}

impl<D: Domain> From<Fr> for SigningKey<D> {
    fn from(sk: Fr) -> Self {
        Self::new_from_field(sk)
    }
}

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
struct SerdeHelper([u8; 32]);

impl<D: Domain> TryFrom<SerdeHelper> for SigningKey<D> {
    type Error = Error;

    fn try_from(helper: SerdeHelper) -> Result<Self, Self::Error> {
        helper.0.try_into()
    }
}

impl<D: Domain> From<SigningKey<D>> for SerdeHelper {
    fn from(sk: SigningKey<D>) -> Self {
        Self(sk.into())
    }
}

impl SigningKey<SpendAuth> {
    /// Randomize this public key with the given `randomizer`.
    pub fn randomize(&self, randomizer: &Fr) -> SigningKey<SpendAuth> {
        let sk = self.sk + randomizer;
        let pk = VerificationKey::from(&sk);
        SigningKey { sk, pk }
    }
}

impl<D: Domain> SigningKey<D> {
    /// Create a new signing key from the supplied `rng`.
    pub fn new<R: RngCore + CryptoRng>(mut rng: R) -> SigningKey<D> {
        let sk = {
            let mut bytes = [0; 64];
            rng.fill_bytes(&mut bytes);
            Fr::from_le_bytes_mod_order(&bytes[..])
        };
        Self::new_from_field(sk)
    }

    /// Use the supplied field element as the signing key directly.
    ///
    /// # Warning
    ///
    /// This function exists to allow custom key derivation; it's the caller's
    /// responsibility to ensure that the input was generated securely.
    pub fn new_from_field(sk: Fr) -> SigningKey<D> {
        let pk = VerificationKey::from(&sk);
        SigningKey { sk, pk }
    }

    /// Create a signature for domain `D` on `msg` using this `SigningKey`.
    // Similar to signature::Signer but without boxed errors.
    pub fn sign<R: RngCore + CryptoRng>(&self, mut rng: R, msg: &[u8]) -> Signature<D> {
        use crate::HStar;

        // Choose a byte sequence uniformly at random of length (\ell_H + 128)/8
        // bytes, where \ell_H is the length of the hash output in bits.
        //
        // For decaf377-reddsa this is (512 + 128)/8 = 80.
        let random_bytes = {
            let mut bytes = [0; 80];
            rng.fill_bytes(&mut bytes);
            bytes
        };

        let nonce = HStar::default()
            .update(&random_bytes[..])
            .update(&self.pk.bytes.bytes[..]) // XXX ugly
            .update(msg)
            .finalize();

        let r_bytes = (&D::basepoint() * &nonce).vartime_compress().0;

        let c = HStar::default()
            .update(&r_bytes[..])
            .update(&self.pk.bytes.bytes[..]) // XXX ugly
            .update(msg)
            .finalize();

        let s_bytes = (nonce + (c * self.sk)).to_bytes();

        Signature {
            r_bytes,
            s_bytes,
            _marker: PhantomData,
        }
    }
}
