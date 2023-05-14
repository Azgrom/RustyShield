use crate::BigEndianBytes;
use core::ops::{Add, AddAssign, BitAnd, Mul, Rem};

#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq, PartialOrd, Ord)]
pub struct KeccakU128Size(u128);

impl Add<usize> for KeccakU128Size {
    type Output = usize;

    fn add(self, rhs: usize) -> Self::Output {
        (self.0 + rhs as u128) as usize
    }
}

impl AddAssign<usize> for KeccakU128Size {
    fn add_assign(&mut self, rhs: usize) {
        self.0 += rhs as u128
    }
}

impl BitAnd for KeccakU128Size {
    type Output = usize;

    fn bitand(self, rhs: Self) -> Self::Output {
        (self.0 & rhs.0) as usize
    }
}

impl BigEndianBytes for KeccakU128Size {
    type BigEndianBytesArray = [u8; 1];

    fn to_be_bytes(&self) -> Self::BigEndianBytesArray {
        [0x80]
    }
}

impl From<u64> for KeccakU128Size {
    fn from(value: u64) -> Self {
        Self(value as u128)
    }
}

impl From<u128> for KeccakU128Size {
    fn from(value: u128) -> Self {
        Self(value)
    }
}

impl From<usize> for KeccakU128Size {
    fn from(value: usize) -> Self {
        Self(value as u128)
    }
}

impl Mul<u32> for KeccakU128Size {
    type Output = Self;

    fn mul(self, rhs: u32) -> Self::Output {
        KeccakU128Size::from(self.0 * rhs as u128)
    }
}

impl Rem for KeccakU128Size {
    type Output = usize;

    fn rem(self, rhs: Self) -> Self::Output {
        (self.0 % rhs.0) as usize
    }
}
