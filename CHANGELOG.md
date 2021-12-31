# CHANGELOG

Entries are listed in reverse chronological order.

# 0.4.0

* Add `TryFrom<&[u8]>` impls to complement array conversions.

# 0.3.0

* Add convenience `.to_bytes()` methods that work like `.into()` but don't require type inference.

# 0.2.0

* Generalize `Eq`, `PartialEq` impls for `VerificationKeyBytes`, `Signature` to avoid a derived `D: Domain + PartialEq` bound.
* Add `Eq`, `PartialEq` impls for `VerificationKey`.

# 0.1.0

* Initial development version
