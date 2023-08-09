# CHANGELOG

Entries are listed in reverse chronological order.

# 0.7.0

* Use 0.5 series of decaf377 dependencies.

# 0.6.0

* Use 0.4 series of Arkworks dependencies.

# 0.5.0

* Add `Ord`, `PartialOrd` to `VerificationKey`, `VerificationKeyBytes` so they can be used with BTrees.

# 0.4.0

* Add `TryFrom<&[u8]>` impls to complement array conversions.

# 0.3.0

* Add convenience `.to_bytes()` methods that work like `.into()` but don't require type inference.

# 0.2.0

* Generalize `Eq`, `PartialEq` impls for `VerificationKeyBytes`, `Signature` to avoid a derived `D: Domain + PartialEq` bound.
* Add `Eq`, `PartialEq` impls for `VerificationKey`.

# 0.1.0

* Initial development version
