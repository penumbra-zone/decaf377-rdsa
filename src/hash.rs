use blake2b_simd::{Params, State};
use decaf377::Fr;

/// Provides H^star, the hash-to-scalar function.
pub struct HStar {
    state: State,
}

impl Default for HStar {
    fn default() -> Self {
        let state = Params::new()
            .hash_length(64)
            .personal(b"decaf377-rdsa---")
            .to_state();
        Self { state }
    }
}

impl HStar {
    /// Add `data` to the hash, and return `Self` for chaining.
    pub fn update(&mut self, data: impl AsRef<[u8]>) -> &mut Self {
        self.state.update(data.as_ref());
        self
    }

    /// Consume `self` to compute the hash output.
    pub fn finalize(&self) -> Fr {
        Fr::from_le_bytes_mod_order(self.state.finalize().as_array())
    }
}
