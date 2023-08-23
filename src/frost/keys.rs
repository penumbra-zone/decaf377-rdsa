//! FROST key shares and key generation.

use crate::{SigningKey, SpendAuth};

use std::collections::HashMap;

use rand_core::RngCore;

use super::*;

pub mod dkg;

/// The identifier list to use when generating key shares.
pub type IdentifierList<'a> = frost::keys::IdentifierList<'a, E>;

/// Allows all participants' keys to be generated using a central, trusted
/// dealer.
pub fn generate_with_dealer<RNG: RngCore + CryptoRng>(
    max_signers: u16,
    min_signers: u16,
    identifiers: IdentifierList,
    mut rng: RNG,
) -> Result<(HashMap<Identifier, SecretShare>, PublicKeyPackage), Error> {
    frost::keys::generate_with_dealer(max_signers, min_signers, identifiers, &mut rng)
}

/// Splits an existing key into FROST shares.
///
/// This is identical to [`generate_with_dealer`] but receives an existing key
/// instead of generating a fresh one. This is useful in scenarios where
/// the key needs to be generated externally or must be derived from e.g. a
/// seed phrase.
pub fn split<R: RngCore + CryptoRng>(
    secret: &SigningKey<SpendAuth>,
    max_signers: u16,
    min_signers: u16,
    identifiers: IdentifierList,
    rng: &mut R,
) -> Result<(HashMap<Identifier, SecretShare>, PublicKeyPackage), Error> {
    // https://github.com/ZcashFoundation/frost/issues/497
    let frost_secret = frost_core::SigningKey::deserialize(secret.to_bytes())?;
    frost::keys::split(&frost_secret, max_signers, min_signers, identifiers, rng)
}

/// Recompute the secret from t-of-n secret shares using Lagrange interpolation.
///
/// This can be used if for some reason the original key must be restored; e.g.
/// if threshold signing is not required anymore.
///
/// This is NOT required to sign with FROST; the whole point of FROST is being
/// able to generate signatures only using the shares, without having to
/// reconstruct the original key.
///
/// The caller is responsible for providing at least `min_signers` shares;
/// if less than that is provided, a different key will be returned.
pub fn reconstruct(secret_shares: &[SecretShare]) -> Result<SigningKey<SpendAuth>, Error> {
    // https://github.com/ZcashFoundation/frost/issues/497
    let frost_secret = frost::keys::reconstruct(secret_shares)?;
    Ok(SigningKey::try_from(frost_secret.serialize()).expect("serialization is valid"))
}

/// Secret and public key material generated by a dealer performing
/// [`generate_with_dealer`].
pub type SecretShare = frost::keys::SecretShare<E>;

/// A secret scalar value representing a signer's share of the group secret.
pub type SigningShare = frost::keys::SigningShare<E>;

/// A public group element that represents a single signer's public verification share.
pub type VerifyingShare = frost::keys::VerifyingShare<E>;

/// A FROST keypair, which can be generated either by a trusted dealer or using a DKG.
///
/// When using a central dealer, [`SecretShare`]s are distributed to
/// participants, who then perform verification, before deriving
/// [`KeyPackage`]s, which they store to later use during signing.
pub type KeyPackage = frost::keys::KeyPackage<E>;

/// Public data that contains all the signers' public keys as well as the
/// group public key.
///
/// Used for verification purposes before publishing a signature.
pub type PublicKeyPackage = frost::keys::PublicKeyPackage<E>;

/// Contains the commitments to the coefficients for our secret polynomial _f_,
/// used to generate participants' key shares.
///
/// [`VerifiableSecretSharingCommitment`] contains a set of commitments to the coefficients (which
/// themselves are scalars) for a secret polynomial f, where f is used to
/// generate each ith participant's key share f(i). Participants use this set of
/// commitments to perform verifiable secret sharing.
///
/// Note that participants MUST be assured that they have the *same*
/// [`VerifiableSecretSharingCommitment`], either by performing pairwise comparison, or by using
/// some agreed-upon public location for publication, where each participant can
/// ensure that they received the correct (and same) value.
pub type VerifiableSecretSharingCommitment = frost::keys::VerifiableSecretSharingCommitment<E>;
