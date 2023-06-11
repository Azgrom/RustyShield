use crate::NBitKeccakState;
use core::hash::Hasher;
use core::ops::{BitAnd, BitAndAssign, BitOr, BitXor, BitXorAssign, Not, Sub};
use rs_hasher_ctx::{ByteArrayWrapper, GenericHasher, HasherContext};
use rs_internal_hasher::HashAlgorithm;
use rs_internal_state::ExtendedOutputFunction;
use rs_n_bit_words::{LittleEndianBytes, NBitWord, Rotate, TSize};

/// `NBitKeccakHasher` is a type that provides the Keccak-nBits hashing algorithm in RustyShield.
///
/// A "Hasher" in the context of cryptographic hashing refers to the object that manages the process of converting input
/// data into a fixed-size sequence of bytes. The Hasher is responsible for maintaining the internal state of the
/// hashing process and providing methods to add more data and retrieve the resulting hash.
///
/// The `NBitKeccakHasher` struct adheres to Rust's `Hasher` trait, enabling you to use it interchangeably with other
/// hashers in Rust. It can be used anywhere a type implementing `Hasher` is required.
///
/// ## Examples
///
/// The following examples demonstrate using `NBitKeccakHasher` with both `Hash` and `Hasher`, and from where the
/// difference comes from:
///
///```rust
/// # use std::hash::{BuildHasher, Hash, Hasher};
/// # use rs_keccak_nbits::NBitKeccakHasher;
/// let data = b"hello";
///
/// // Using Hash
/// let mut keccakhasher = NBitKeccakHasher::<u8, 4, 20>::default();
/// data.hash(&mut keccakhasher);
/// let result_via_hash = keccakhasher.finish();
///
/// // Using Hasher
/// let mut keccakhasher = NBitKeccakHasher::<u8, 4, 20>::default();
/// keccakhasher.write(data);
/// let result_via_hasher = keccakhasher.finish();
///
/// // Simulating the Hash inners
/// let mut keccakhasher = NBitKeccakHasher::<u8, 4, 20>::default();
/// keccakhasher.write_usize(data.len());
/// keccakhasher.write(data);
/// let simulated_hash_result = keccakhasher.finish();
///
/// assert_ne!(result_via_hash, result_via_hasher);
/// assert_eq!(result_via_hash, simulated_hash_result);
///```
#[derive(Clone, Debug, Default, Eq, Hash, PartialEq)]
pub struct NBitKeccakHasher<T, const RATE: usize, const OUTPUT_SIZE: usize>(
    GenericHasher<NBitKeccakState<T, RATE, OUTPUT_SIZE>, OUTPUT_SIZE>,
)
where
    T: BitAnd
        + BitAndAssign
        + BitOr<NBitWord<T>, Output = NBitWord<T>>
        + BitXor<Output = T>
        + BitXorAssign
        + Copy
        + Default
        + Not<Output = T>,
    NBitWord<T>: From<u64> + LittleEndianBytes + Not<Output = NBitWord<T>> + Rotate + TSize<T>,
    u32: Sub<NBitWord<T>, Output = NBitWord<T>>;

impl<T, const RATE: usize, const OUTPUT_SIZE: usize> From<NBitKeccakHasher<T, RATE, OUTPUT_SIZE>>
    for NBitKeccakState<T, RATE, OUTPUT_SIZE>
where
    T: Copy
        + Default
        + BitAnd
        + BitAndAssign
        + BitOr<NBitWord<T>, Output = NBitWord<T>>
        + BitXor<Output = T>
        + BitXorAssign
        + Not<Output = T>,
    NBitWord<T>: From<u64> + LittleEndianBytes + Not<Output = NBitWord<T>> + Rotate + TSize<T>,
    u32: Sub<NBitWord<T>, Output = NBitWord<T>>,
{
    fn from(value: NBitKeccakHasher<T, RATE, OUTPUT_SIZE>) -> Self {
        value.0.state
    }
}

impl<T, const RATE: usize, const OUTPUT_SIZE: usize> From<NBitKeccakState<T, RATE, OUTPUT_SIZE>>
    for NBitKeccakHasher<T, RATE, OUTPUT_SIZE>
    where
        T: Copy
        + Default
        + BitAnd
        + BitAndAssign
        + BitOr<NBitWord<T>, Output = NBitWord<T>>
        + BitXor<Output = T>
        + BitXorAssign
        + Not<Output = T>,
        NBitWord<T>: From<u64> + LittleEndianBytes + Not<Output = NBitWord<T>> + Rotate + TSize<T>,
        u32: Sub<NBitWord<T>, Output = NBitWord<T>>,
{
    fn from(value: NBitKeccakState<T, RATE, OUTPUT_SIZE>) -> Self {
        Self(GenericHasher {
            padding: <NBitKeccakState<T, RATE, OUTPUT_SIZE> as HashAlgorithm>::Padding::default(),
            state: value,
        })
    }
}

impl<T, const RATE: usize, const OUTPUT_SIZE: usize> Hasher for NBitKeccakHasher<T, RATE, OUTPUT_SIZE>
where
    T: BitAnd
        + BitAndAssign
        + BitOr<NBitWord<T>, Output = NBitWord<T>>
        + BitXor<Output = T>
        + BitXorAssign
        + Copy
        + Default
        + Not<Output = T>,
    NBitWord<T>: From<u64> + LittleEndianBytes + Not<Output = NBitWord<T>> + Rotate + TSize<T>,
    u32: Sub<NBitWord<T>, Output = NBitWord<T>>,
{
    fn finish(&self) -> u64 {
        Hasher::finish(&self.0)
    }

    fn write(&mut self, bytes: &[u8]) {
        self.0.write(bytes)
    }
}

impl<T, const RATE: usize, const OUTPUT_SIZE: usize> HasherContext<OUTPUT_SIZE>
    for NBitKeccakHasher<T, RATE, OUTPUT_SIZE>
where
    T: BitAnd
        + BitAndAssign
        + BitOr<NBitWord<T>, Output = NBitWord<T>>
        + BitXor<Output = T>
        + BitXorAssign
        + Copy
        + Default
        + Not<Output = T>,
    NBitWord<T>: From<u64> + LittleEndianBytes + Not<Output = NBitWord<T>> + Rotate + TSize<T>,
    u32: Sub<NBitWord<T>, Output = NBitWord<T>>,
{
    type Output = ByteArrayWrapper<OUTPUT_SIZE>;

    fn finish(&mut self) -> Self::Output {
        HasherContext::finish(&mut self.0).squeeze().into()
    }
}
