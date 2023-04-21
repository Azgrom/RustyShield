use crate::BigEndianBytes;
use core::ops::{AddAssign, BitAnd, Mul};

#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq, PartialOrd, Ord)]
pub struct U64Size(u64);

impl AddAssign<usize> for U64Size {
    fn add_assign(&mut self, rhs: usize) {
        self.0 += rhs as u64
    }
}

impl BitAnd for U64Size {
    type Output = usize;

    fn bitand(self, rhs: Self) -> Self::Output {
        (self.0 & rhs.0) as usize
    }
}

impl BitAnd<usize> for U64Size {
    type Output = usize;

    fn bitand(self, rhs: usize) -> Self::Output {
        (self.0 & rhs as u64) as usize
    }
}

impl BigEndianBytes for U64Size {
    type BigEndianBytesArray = [u8; 8];

    fn to_be_bytes(&self) -> Self::BigEndianBytesArray {
        self.0.to_be_bytes()
    }
}

impl From<u64> for U64Size {
    fn from(value: u64) -> Self {
        Self(value)
    }
}

impl From<u128> for U64Size {
    fn from(value: u128) -> Self {
        Self(value as u64)
    }
}

impl From<usize> for U64Size {
    fn from(value: usize) -> Self {
        Self(value as u64)
    }
}

impl Mul<u32> for U64Size {
    type Output = Self;

    fn mul(self, rhs: u32) -> Self::Output {
        U64Size::from(self.0 * rhs as u64)
    }
}
