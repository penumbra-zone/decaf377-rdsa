# decaf377-rdsa

[![Crates.io][crates-badge]][crates-url]

[crates-badge]: https://img.shields.io/crates/v/decaf377-rdsa.svg
[crates-url]: https://crates.io/crates/decaf377-rdsa

`decaf377-rdsa` is a variant of RedDSA, instantiated using the `decaf377` group.

Signatures are parameterized by domain (for instance, `Binding` and
`SpendAuth`); this library distinguishes different domains in the type system
using the `SigType` trait as a type-level enum.

In addition to the `Signature`, `SigningKey`, `VerificationKey` types,
the library also provides `VerificationKeyBytes`, a [refinement] of a
`[u8; 32]` indicating that bytes represent an encoding of a RedJubjub
verification key. This allows the `VerificationKey` type to cache
verification checks related to the verification key encoding.

## WARNING

This code is a work-in-progress, and the entire specification is still subject
to change.  In particular, it's likely that the basepoint used for binding
signatures will change in the future as the `decaf377` spec evolves.

## Examples

Creating a spend authorization signature, serializing and deserializing it, and
verifying the signature:

```
# use std::convert::TryFrom;
use rand::thread_rng;
use decaf377_rdsa::*;

let msg = b"Hello!";

// Generate a secret key and sign the message
let sk = SigningKey::<SpendAuth>::new(thread_rng());
let sig = sk.sign(thread_rng(), msg);

// Types can be converted to raw byte arrays using From/Into
let sig_bytes: [u8; 64] = sig.into();
let pk_bytes: [u8; 32] = VerificationKey::from(&sk).into();

// Deserialize and verify the signature.
let sig: Signature<SpendAuth> = sig_bytes.into();
assert!(
    VerificationKey::try_from(pk_bytes)
        .and_then(|pk| pk.verify(msg, &sig))
        .is_ok()
);
```

## About

This library is based on the [`redjubjub` crate][redjubjub_crate].

[redjubjub]: https://zips.z.cash/protocol/protocol.pdf#concretereddsa
[redjubjub_crate]: https://crates.io/crates/redjubjub
[refinement]: https://en.wikipedia.org/wiki/Refinement_type
[sealed]: https://rust-lang.github.io/api-guidelines/future-proofing.html#sealed-traits-protect-against-downstream-implementations-c-sealed
