use core::ops::{BitAnd, BitOr, BitXor, Shl, Shr, Sub};

pub trait TSize<T>
where
    Self: BitAnd<Output = Self>
        + BitOr<Output = Self>
        + BitXor<Output = Self>
        + Copy
        + Shl<Output = Self>
        + Shr<Output = Self>
        + Sized,
    u32: Sub<Self, Output = Self>,
{
    const BITS: u32;
    const SIZE: usize;

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

    fn rotate(x: Self, left: Self, right: Self) -> Self {
        (x << left) | (x >> right)
    }

    fn rotate_left(self, n: Self) -> Self {
        Self::rotate(self, n, Self::BITS - n)
    }

    fn rotate_right(self, n: Self) -> Self {
        Self::rotate(self, Self::BITS - n, n)
    }

    fn gamma0(self) -> Self;
    fn gamma1(self) -> Self;
    fn sigma0(self) -> Self;
    fn sigma1(self) -> Self;
}
