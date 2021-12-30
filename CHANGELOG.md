# CHANGELOG

Entries are listed in reverse chronological order.

# 0.2.0

* Generalize `Eq`, `PartialEq` impls for `VerificationKeyBytes`, `Signature` to avoid a derived `D: Domain + PartialEq` bound.
* Add `Eq`, `PartialEq` impls for `VerificationKey`.

# 0.1.0

* Initial development version
