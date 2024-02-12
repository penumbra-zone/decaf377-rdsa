use decaf377::Fr;
use rand_core::{CryptoRng, RngCore};

use crate::{Domain, Error, Signature, SpendAuth, VerificationKey};

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
        let sk = Fr::from_bytes_checked(&bytes).map_err(|_| Error::MalformedSigningKey)?;
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
        let mut bonus_randomness = [0u8; 48];
        rng.fill_bytes(&mut bonus_randomness);
        self.sign_inner(&bonus_randomness, msg)
    }

    /// Create a signature for domain `D` on `msg` using this `SigningKey`.
    ///
    /// Prefer `sign`, unless you know you need deterministic signatures.
    pub fn sign_deterministic(&self, msg: &[u8]) -> Signature<D> {
        let bonus_randomness = [0u8; 48];
        self.sign_inner(&bonus_randomness, msg)
    }

    fn sign_inner(&self, bonus_randomness: &[u8; 48], msg: &[u8]) -> Signature<D> {
        use crate::HStar;

        // We deviate from RedDSA as specified in the Zcash protocol spec and instead
        // use a construction in line with Trevor Perrin's synthetic nonces:
        // https://moderncrypto.org/mail-archive/curves/2017/000925.html
        // Rather than choosing T to be 80 random bytes (\ell_H + 128)/8 as in RedDSA,
        // we choose T to be 32-byte sk || 48-byte bonus_randomness.
        // In this way, even in the case of an RNG failure, we fall back to secure but
        // deterministic signing.
        let nonce = HStar::default()
            .update(&self.sk.to_bytes()[..])
            .update(&bonus_randomness[..])
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

        Signature::from_parts(r_bytes, s_bytes)
    }
}

#[cfg(feature = "std")]
mod std_only {
    use super::*;
    use std::fmt;

    use crate::Binding;

    impl fmt::Debug for SigningKey<Binding> {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_tuple("SigningKey<Binding>")
                .field(&hex::encode(&<[u8; 32]>::from(*self)))
                .finish()
        }
    }

    impl fmt::Debug for SigningKey<SpendAuth> {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_tuple("SigningKey<SpendAuth>")
                .field(&hex::encode(&<[u8; 32]>::from(*self)))
                .finish()
        }
    }
}

#[cfg(feature = "std")]
pub use std_only::*;
