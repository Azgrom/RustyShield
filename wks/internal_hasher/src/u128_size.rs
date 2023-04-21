use crate::BigEndianBytes;
use core::ops::{AddAssign, BitAnd, Mul};

#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq, PartialOrd, Ord)]
pub struct U128Size(u128);

impl AddAssign<usize> for U128Size {
    fn add_assign(&mut self, rhs: usize) {
        self.0 += rhs as u128
    }
}

impl BitAnd for U128Size {
    type Output = usize;

    fn bitand(self, rhs: Self) -> Self::Output {
        (self.0 & rhs.0) as usize
    }
}

impl BigEndianBytes for U128Size {
    type BigEndianBytesArray = [u8; 16];

    fn to_be_bytes(&self) -> Self::BigEndianBytesArray {
        self.0.to_be_bytes()
    }
}

impl From<u64> for U128Size {
    fn from(value: u64) -> Self {
        Self(value as u128)
    }
}

impl From<u128> for U128Size {
    fn from(value: u128) -> Self {
        Self(value)
    }
}

impl From<usize> for U128Size {
    fn from(value: usize) -> Self {
        Self(value as u128)
    }
}

impl Mul<u32> for U128Size {
    type Output = Self;

    fn mul(self, rhs: u32) -> Self::Output {
        U128Size::from(self.0 * rhs as u128)
    }
}
