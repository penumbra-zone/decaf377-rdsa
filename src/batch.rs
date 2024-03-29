//! Performs batch `decaf377-rdsa` signature verification.
//!
//! Batch verification asks whether *all* signatures in some set are valid,
//! rather than asking whether *each* of them is valid. This allows sharing
//! computations among all signature verifications, performing less work overall
//! at the cost of higher latency (the entire batch must complete), complexity of
//! caller code (which must assemble a batch of signatures across work-items),
//! and loss of the ability to easily pinpoint failing signatures.
//!

use std::convert::TryFrom;

use decaf377::{Element, Fr};
use rand_core::{CryptoRng, RngCore};

use crate::{
    domain::Sealed, Binding, Error, HStar, Signature, SpendAuth, VerificationKey,
    VerificationKeyBytes,
};

// Shim to generate a random 128bit Fr value.
fn gen_128_bits<R: RngCore + CryptoRng>(mut rng: R) -> Fr {
    let lo = rng.next_u64() as u128;
    let hi = rng.next_u64() as u128;
    (lo + (hi << 64)).into()
}

#[derive(Clone, Debug)]
enum Inner {
    SpendAuth {
        vk_bytes: VerificationKeyBytes<SpendAuth>,
        sig: Signature<SpendAuth>,
        c: Fr,
    },
    Binding {
        vk_bytes: VerificationKeyBytes<Binding>,
        sig: Signature<Binding>,
        c: Fr,
    },
}

/// A batch verification item.
///
/// This struct exists to allow batch processing to be decoupled from the
/// lifetime of the message. This is useful when using the batch verification API
/// in an async context.
#[derive(Clone, Debug)]
pub struct Item {
    inner: Inner,
}

impl<'msg, M: AsRef<[u8]>>
    From<(
        VerificationKeyBytes<SpendAuth>,
        Signature<SpendAuth>,
        &'msg M,
    )> for Item
{
    fn from(
        (vk_bytes, sig, msg): (
            VerificationKeyBytes<SpendAuth>,
            Signature<SpendAuth>,
            &'msg M,
        ),
    ) -> Self {
        // Compute c now to avoid dependency on the msg lifetime.
        let c = HStar::default()
            .update(&sig.r_bytes()[..])
            .update(&vk_bytes.bytes[..])
            .update(msg)
            .finalize();
        Self {
            inner: Inner::SpendAuth { vk_bytes, sig, c },
        }
    }
}

impl<'msg, M: AsRef<[u8]>> From<(VerificationKeyBytes<Binding>, Signature<Binding>, &'msg M)>
    for Item
{
    fn from(
        (vk_bytes, sig, msg): (VerificationKeyBytes<Binding>, Signature<Binding>, &'msg M),
    ) -> Self {
        // Compute c now to avoid dependency on the msg lifetime.
        let c = HStar::default()
            .update(&sig.r_bytes()[..])
            .update(&vk_bytes.bytes[..])
            .update(msg)
            .finalize();
        Self {
            inner: Inner::Binding { vk_bytes, sig, c },
        }
    }
}

impl Item {
    /// Perform non-batched verification of this `Item`.
    ///
    /// This is useful (in combination with `Item::clone`) for implementing fallback
    /// logic when batch verification fails. In contrast to
    /// [`VerificationKey::verify`](crate::VerificationKey::verify), which requires
    /// borrowing the message data, the `Item` type is unlinked from the lifetime of
    /// the message.
    #[allow(non_snake_case)]
    pub fn verify_single(self) -> Result<(), Error> {
        match self.inner {
            Inner::Binding { vk_bytes, sig, c } => VerificationKey::<Binding>::try_from(vk_bytes)
                .and_then(|vk| vk.verify_prehashed(&sig, c)),
            Inner::SpendAuth { vk_bytes, sig, c } => {
                VerificationKey::<SpendAuth>::try_from(vk_bytes)
                    .and_then(|vk| vk.verify_prehashed(&sig, c))
            }
        }
    }
}

#[derive(Default)]
/// A batch verification context.
pub struct Verifier {
    /// Signature data queued for verification.
    signatures: Vec<Item>,
}

impl Verifier {
    /// Construct a new batch verifier.
    pub fn new() -> Verifier {
        Verifier::default()
    }

    /// Queue an Item for verification.
    pub fn queue<I: Into<Item>>(&mut self, item: I) {
        self.signatures.push(item.into());
    }

    /// Perform batch verification, returning `Ok(())` if all signatures were
    /// valid and `Err` otherwise.
    ///
    /// The batch verification equation is:
    ///
    /// ```ascii
    /// h_G * -[sum(z_i * s_i)]P_G + sum([z_i]R_i + [z_i * c_i]VK_i) = 0_G
    /// ```
    ///
    /// which we split out into:
    ///
    /// ```ascii
    /// h_G * -[sum(z_i * s_i)]P_G + sum([z_i]R_i) + sum([z_i * c_i]VK_i) = 0_G
    /// ```
    ///
    /// so that we can use multiscalar multiplication speedups.
    ///
    /// where for each signature i,
    /// - VK_i is the verification key;
    /// - R_i is the signature's R value;
    /// - s_i is the signature's s value;
    /// - c_i is the hash of the message and other data;
    /// - z_i is a random 128-bit Scalar;
    /// - h_G is the cofactor of the group;
    /// - P_G is the generator of the subgroup;
    ///
    /// Since `decaf377-rdsa` uses a different generator for each signature
    /// domain, we have a separate scalar accumulator for each domain, but we
    /// can still amortize computation nicely in one multiscalar multiplication:
    ///
    /// ```ascii
    /// h_G * ( [-sum(z_i * s_i): i_type == SpendAuth]P_SpendAuth + [-sum(z_i * s_i): i_type == Binding]P_Binding + sum([z_i]R_i) + sum([z_i * c_i]VK_i) ) = 0_G
    /// ```
    ///
    /// As follows elliptic curve scalar multiplication convention,
    /// scalar variables are lowercase and group point variables
    /// are uppercase. This does not exactly match the RedDSA
    /// notation in the [Zcash protocol specification §B.1][ps].
    ///
    /// [ps]: https://zips.z.cash/protocol/protocol.pdf#reddsabatchverify
    #[allow(non_snake_case)]
    pub fn verify<R: RngCore + CryptoRng>(self, mut rng: R) -> Result<(), Error> {
        let n = self.signatures.len();

        let mut VK_coeffs = Vec::with_capacity(n);
        let mut VKs = Vec::with_capacity(n);
        let mut R_coeffs = Vec::with_capacity(self.signatures.len());
        let mut Rs = Vec::with_capacity(self.signatures.len());
        let mut P_spendauth_coeff = Fr::ZERO;
        let mut P_binding_coeff = Fr::ZERO;

        for item in self.signatures.iter() {
            let (s_bytes, r_bytes, c) = match item.inner {
                Inner::SpendAuth { sig, c, .. } => (sig.s_bytes(), sig.r_bytes(), c),
                Inner::Binding { sig, c, .. } => (sig.s_bytes(), sig.r_bytes(), c),
            };

            let s = Fr::from_bytes_checked(&s_bytes).map_err(|_| Error::InvalidSignature)?;
            let R = decaf377::Encoding(r_bytes)
                .vartime_decompress()
                .map_err(|_| Error::InvalidSignature)?;

            let VK = match item.inner {
                Inner::SpendAuth { vk_bytes, .. } => {
                    VerificationKey::<SpendAuth>::try_from(vk_bytes.bytes)?.point
                }
                Inner::Binding { vk_bytes, .. } => {
                    VerificationKey::<Binding>::try_from(vk_bytes.bytes)?.point
                }
            };

            let z = gen_128_bits(&mut rng);

            let P_coeff = z * s;
            match item.inner {
                Inner::SpendAuth { .. } => {
                    P_spendauth_coeff -= P_coeff;
                }
                Inner::Binding { .. } => {
                    P_binding_coeff -= P_coeff;
                }
            };

            R_coeffs.push(z);
            Rs.push(R);

            VK_coeffs.push(z * c);
            VKs.push(VK);
        }

        use std::iter::once;

        let scalars = once(&P_spendauth_coeff)
            .chain(once(&P_binding_coeff))
            .chain(VK_coeffs.iter())
            .chain(R_coeffs.iter());

        let basepoints = [SpendAuth::basepoint(), Binding::basepoint()];
        let points = basepoints.iter().chain(VKs.iter()).chain(Rs.iter());

        let check = Element::vartime_multiscalar_mul(scalars, points);

        if check.is_identity() {
            Ok(())
        } else {
            Err(Error::InvalidSignature)
        }
    }
}
