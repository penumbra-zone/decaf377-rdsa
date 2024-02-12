use core::fmt;

/// An error related to `decaf377-rdsa` signatures.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum Error {
    /// The encoding of a signing key was malformed.
    MalformedSigningKey,
    /// The encoding of a verification key was malformed.
    MalformedVerificationKey,
    /// Signature verification failed.
    InvalidSignature,
    /// Occurs when reading from a slice of the wrong length.
    WrongSliceLength { expected: usize, found: usize },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MalformedSigningKey => f.write_str("Malformed signing key encoding."),
            Self::MalformedVerificationKey => f.write_str("Malformed verification key encoding."),
            Self::InvalidSignature => f.write_str("Invalid signature."),
            Self::WrongSliceLength { expected, found } => {
                f.write_str("Wrong slice length, expected ")?;
                expected.fmt(f)?;
                f.write_str(", found ")?;
                found.fmt(f)
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}
