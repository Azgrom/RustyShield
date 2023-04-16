use crate::BigEndianBytes;
use core::ops::{AddAssign, BitAnd, Mul};

#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq, PartialOrd, Ord)]
pub struct U128Size(u128);

impl AddAssign<u64> for U128Size {
    fn add_assign(&mut self, rhs: u64) {
        self.0 += rhs as u128
    }
}

impl BitAnd<u64> for U128Size {
    type Output = u64;

    fn bitand(self, rhs: u64) -> Self::Output {
        (self.0 & rhs as u128) as u64
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

impl Mul<u32> for U128Size {
    type Output = Self;

    fn mul(self, rhs: u32) -> Self::Output {
        U128Size::from(self.0 * rhs as u128)
    }
}
