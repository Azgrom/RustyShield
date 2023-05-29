use crate::Shake256State;
use core::hash::Hasher;
use hash_ctx_lib::{ByteArrayWrapper, GenericHasher, HasherContext};
use internal_hasher::HashAlgorithm;
use internal_state::ExtendedOutputFunction;

/// `Shake256State` represents the state of a SHAKE128 hashing process.
///
/// It holds intermediate hash calculations. However, it's important to note that starting a hashing
/// process from an arbitrary `Shake256State` is not equivalent to resuming the original process that
/// produced that state. Instead, it begins a new hashing process with a different set of initial values.
///
/// Therefore, a `Shake256State` extracted from a `Shake256Hasher` should not be used with the expectation
/// of continuing the hashing operation from where it left off in the original `Shake256Hasher`. It is
/// a snapshot of a particular point in the process, not a means to resume the process.
///
/// # Example
///
/// This example demonstrates how to persist the state of a SHAKE128 hash operation:
///
/// ```rust
/// # use std::hash::{BuildHasher, Hash, Hasher};
/// # use rs_shake256::{Shake256Hasher, Shake256State};
/// let hello = b"hello";
/// let world = b" world";
/// let default_shake256state = Shake256State::<20>::default();
///
/// let mut default_shake256hasher = default_shake256state.build_hasher();
/// default_shake256hasher.write(hello);
///
/// let intermediate_state: Shake256State<20> = default_shake256hasher.clone().into();
///
/// default_shake256hasher.write(world);
///
/// let mut from_shake256state: Shake256Hasher<20> = intermediate_state.into();
/// from_shake256state.write(world);
///
/// let default_hello_world_result = default_shake256hasher.finish();
/// let from_arbitrary_state_result = from_shake256state.finish();
/// assert_ne!(default_hello_world_result, from_arbitrary_state_result);
/// ```
///
/// ## Note
/// In this example, even though the internal states are the same between `default_shake128hasher` and `from_shake128state`
/// before the `Hasher::finish_xof` call, the results are different due to `from_shake128state` being instantiated with an empty
/// pad while the `default_shake128hasher`'s pad is already populated with `b"hello"`.
#[derive(Clone, Debug, Default, Eq, Hash, PartialEq)]
pub struct Shake256Hasher<const OUTPUT_SIZE: usize>(GenericHasher<Shake256State<OUTPUT_SIZE>, OUTPUT_SIZE>);

impl<const OUTPUT_SIZE: usize> From<Shake256Hasher<OUTPUT_SIZE>> for Shake256State<OUTPUT_SIZE> {
    fn from(value: Shake256Hasher<OUTPUT_SIZE>) -> Self {
        value.0.state
    }
}

impl<const OUTPUT_SIZE: usize> From<Shake256State<OUTPUT_SIZE>> for Shake256Hasher<OUTPUT_SIZE> {
    fn from(value: Shake256State<OUTPUT_SIZE>) -> Self {
        Self(GenericHasher{
            padding: <Shake256State<OUTPUT_SIZE> as HashAlgorithm>::Padding::default(),
            state: value
        })
    }
}

impl<const OUTPUT_SIZE: usize> Hasher for Shake256Hasher<OUTPUT_SIZE> {
    fn finish(&self) -> u64 {
        Hasher::finish(&self.0)
    }

    fn write(&mut self, bytes: &[u8]) {
        self.0.write(bytes)
    }
}

impl<const OUTPUT_SIZE: usize> HasherContext<OUTPUT_SIZE> for Shake256Hasher<OUTPUT_SIZE> {
    type Output = ByteArrayWrapper<OUTPUT_SIZE>;

    fn finish(&mut self) -> Self::Output {
        HasherContext::finish(&mut self.0).squeeze().into()
    }
}
