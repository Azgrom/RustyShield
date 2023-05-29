use core::ops::{BitAnd, BitOr, BitXor, Shl, Shr, Sub};

pub trait TSize<T>
    where
        Self: BitAnd<Output = Self>
        + BitOr<Output = Self>
        + BitXor<Output = Self>
        + Copy
        + Shl<T>
        + Shr<T>
        + Sized,
        T: BitOr<Self, Output = Self>,
        u32: Sub<Self, Output = Self>,
{
    const BITS: u32;
    const SIZE: usize;

    fn gamma0(&self) -> Self;
    fn gamma1(&self) -> Self;
    fn sigma0(&self) -> Self;
    fn sigma1(&self) -> Self;

    #[inline(always)]
    fn ch(x: Self, y: Self, z: Self) -> Self {
        ((y ^ z) & x) ^ z
    }

    #[inline(always)]
    fn maj(x: Self, y: Self, z: Self) -> Self {
        (x & y) | ((x | y) & z)
    }

    #[inline(always)]
    fn parity(x: Self, y: Self, z: Self) -> Self {
        x ^ y ^ z
    }
}
