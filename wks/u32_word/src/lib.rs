#![no_std]
use core::{
    fmt::{Formatter, LowerHex, Result, UpperHex},
    hash::{Hash, Hasher},
    ops::{Add, AddAssign, BitAnd, BitOr, BitXor, Shr},
};

#[cfg(test)]
mod test_trait_impls;

#[derive(Clone, Copy, Debug)]
pub struct U32Word(u32);

impl U32Word {
    #[inline(always)]
    pub fn ch(x: U32Word, y: U32Word, z: U32Word) -> Self {
        ((y ^ z) & x) ^ z
    }

    #[inline(always)]
    pub fn parity(x: U32Word, y: U32Word, z: U32Word) -> Self {
        x ^ y ^ z
    }

    #[inline(always)]
    pub fn maj(x: U32Word, y: U32Word, z: U32Word) -> Self {
        (x & y) | ((x | y) & z)
    }

    pub fn rotate_left(&self, n: u32) -> Self {
        Self(self.0.rotate_left(n))
    }

    pub fn rotate_right(&self, n: u32) -> Self {
        Self(self.0.rotate_right(n))
    }

    pub fn gamma0(self) -> u32 {
        (self.rotate_right(7) ^ self.rotate_right(18) ^ (self >> 3)).into()
    }

    pub fn gamma1(self) -> Self {
        self.rotate_right(17) ^ self.rotate_right(19) ^ (self >> 10)
    }

    fn sigma0(&self) -> Self {
        self.rotate_right(2) ^ self.rotate_right(13) ^ self.rotate_right(22)
    }

    fn sigma1(&self) -> Self {
        self.rotate_right(6) ^ self.rotate_right(11) ^ self.rotate_right(25)
    }

    pub fn rnd(
        a: U32Word,
        b: U32Word,
        c: U32Word,
        d: &mut U32Word,
        e: U32Word,
        f: U32Word,
        g: U32Word,
        h: &mut U32Word,
        w: U32Word,
        k: u32,
    ) {
        let t0 = *h + e.sigma1() + Self::ch(e, f, g) + k + w;
        *d += t0;
        *h = t0 + a.sigma0() + Self::maj(a, b, c);
    }

    pub fn from_be_bytes(bytes: [u8; 4]) -> Self {
        Self(u32::from_be_bytes(bytes))
    }

    pub fn to_be_bytes(&self) -> [u8; 4] {
        self.0.to_be_bytes()
    }
}

impl Add for U32Word {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Self(self.0.wrapping_add(rhs.0))
    }
}

impl Add<u32> for U32Word {
    type Output = Self;

    fn add(self, rhs: u32) -> Self::Output {
        Self(self.0.wrapping_add(rhs))
    }
}

impl Add<U32Word> for u32 {
    type Output = U32Word;

    fn add(self, rhs: U32Word) -> Self::Output {
        U32Word(self.wrapping_add(rhs.0))
    }
}

impl AddAssign for U32Word {
    fn add_assign(&mut self, rhs: Self) {
        *self = *self + rhs;
    }
}

impl BitAnd for U32Word {
    type Output = Self;

    fn bitand(self, rhs: Self) -> Self::Output {
        Self(self.0 & rhs.0)
    }
}

impl BitOr for U32Word {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        Self(self.0 | rhs.0)
    }
}

impl BitXor for U32Word {
    type Output = Self;

    fn bitxor(self, rhs: Self) -> Self::Output {
        Self(self.0 ^ rhs.0)
    }
}

impl Default for U32Word {
    fn default() -> Self {
        Self(u32::MIN)
    }
}

impl LowerHex for U32Word {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        LowerHex::fmt(&self.0, f)
    }
}

impl UpperHex for U32Word {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        UpperHex::fmt(&self.0, f)
    }
}

impl From<u32> for U32Word {
    fn from(value: u32) -> Self {
        Self(value)
    }
}

impl From<U32Word> for u32 {
    fn from(value: U32Word) -> Self {
        value.0
    }
}

impl From<U32Word> for u64 {
    fn from(value: U32Word) -> Self {
        value.0 as u64
    }
}

impl Hash for U32Word {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.hash(state)
    }
}

impl PartialEq for U32Word {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl PartialEq<u32> for U32Word {
    fn eq(&self, other: &u32) -> bool {
        self.0 == *other
    }
}

impl Shr<u8> for U32Word {
    type Output = Self;

    fn shr(self, rhs: u8) -> Self::Output {
        Self(self.0 >> rhs)
    }
}
