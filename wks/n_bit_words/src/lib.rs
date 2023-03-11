#![no_std]

use core::{
    num::Wrapping,
    hash::{Hash, Hasher},
    fmt::{Formatter, LowerHex, UpperHex},
    ops::{Add, AddAssign, BitAnd, BitOr, BitXor, Shl, Shr, Sub}
};
pub use crate::t_size::TSize;

mod t_size;
mod u64_words;

#[cfg(test)]
mod unit_tests;

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct NBitWord<T>(Wrapping<T>);

impl TSize<u32> for NBitWord<u32> {
    const BITS: u32 = u32::BITS;
    const SIZE: usize = 4;

    fn gamma0(self) -> Self {
        self.rotate_right(Self(Wrapping(7))) ^ self.rotate_right(Self(Wrapping(18))) ^ (self >> Self(Wrapping(3)))
    }

    fn gamma1(self) -> Self {
        self.rotate_right(Self(Wrapping(17))) ^ self.rotate_right(Self(Wrapping(19))) ^ (self >> Self(Wrapping(10)))
    }

    fn sigma0(self) -> Self {
        self.rotate_right(Self(Wrapping(2)))
            ^ self.rotate_right(Self(Wrapping(13)))
            ^ self.rotate_right(Self(Wrapping(22)))
    }

    fn sigma1(self) -> Self {
        self.rotate_right(Self(Wrapping(6)))
            ^ self.rotate_right(Self(Wrapping(11)))
            ^ self.rotate_right(Self(Wrapping(25)))
    }
}

impl TSize<u64> for NBitWord<u64> {
    const BITS: u32 = u64::BITS;
    const SIZE: usize = 8;

    fn gamma0(self) -> Self {
        self.rotate_right(Self(Wrapping(1))) ^ self.rotate_right(Self(Wrapping(8))) ^ (self >> Self(Wrapping(7)))
    }

    fn gamma1(self) -> Self {
        self.rotate_right(Self(Wrapping(19))) ^ self.rotate_right(Self(Wrapping(61))) ^ (self >> Self(Wrapping(6)))
    }

    fn sigma0(self) -> Self {
        self.rotate_right(Self(Wrapping(28)))
            ^ self.rotate_right(Self(Wrapping(34)))
            ^ self.rotate_right(Self(Wrapping(39)))
    }

    fn sigma1(self) -> Self {
        self.rotate_right(Self(Wrapping(14)))
            ^ self.rotate_right(Self(Wrapping(18)))
            ^ self.rotate_right(Self(Wrapping(41)))
    }
}

impl<T> Add for NBitWord<T>
where Wrapping<T>: Add<Output = Wrapping<T>>
{
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Self(self.0 + rhs.0)
    }
}

impl Add<u32> for NBitWord<u32> {
    type Output = Self;

    fn add(self, rhs: u32) -> Self::Output {
        self + Self(Wrapping(rhs))
    }
}

impl Add<NBitWord<u32>> for u32 {
    type Output = NBitWord<u32>;

    fn add(self, rhs: NBitWord<u32>) -> Self::Output {
        NBitWord(Wrapping(self)) + rhs
    }
}

impl<T> AddAssign for NBitWord<T>
where Wrapping<T>: AddAssign
{
    fn add_assign(&mut self, rhs: Self) {
        self.0 += rhs.0
    }
}

impl<T> BitAnd for NBitWord<T>
where T: BitAnd<Output = T>
{
    type Output = Self;

    fn bitand(self, rhs: Self) -> Self::Output {
        Self(Wrapping(self.0.0 & rhs.0.0))
    }
}

impl<T> BitOr for NBitWord<T>
where T: BitOr<Output = T>
{
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        Self(Wrapping(self.0.0 | rhs.0.0))
    }
}

impl<T> BitXor for NBitWord<T>
where T: BitXor<Output = T>
{
    type Output = Self;

    fn bitxor(self, rhs: Self) -> Self::Output {
        Self(Wrapping(self.0.0 ^ rhs.0.0))
    }
}

impl<T> From<T> for NBitWord<T> {
    fn from(value: T) -> Self {
        Self(Wrapping(value))
    }
}

impl From<NBitWord<u32>> for u32 {
    fn from(value: NBitWord<u32>) -> Self {
        value.0.0
    }
}

impl From<[u8; 4]> for NBitWord<u32> {
    fn from(value: [u8; 4]) -> Self {
        u32::from_be_bytes([
            value[0],
            value[1],
            value[2],
            value[3],
        ]).into()
    }
}

impl From<NBitWord<u32>> for u64 {
    fn from(value: NBitWord<u32>) -> Self {
        value.0.0 as u64
    }
}

impl From<NBitWord<u64>> for u64 {
    fn from(value: NBitWord<u64>) -> Self {
        value.0.0
    }
}

impl From<[u8; 8]> for NBitWord<u64> {
    fn from(value: [u8; 8]) -> Self {
        u64::from_be_bytes([
            value[0],
            value[1],
            value[2],
            value[3],
            value[4],
            value[5],
            value[6],
            value[7],
        ]).into()
    }
}

impl<T> Hash for NBitWord<T>
where T: Hash
{
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.0.hash(state)
    }
}

impl<T> LowerHex for NBitWord<T>
where T: LowerHex
{
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        LowerHex::fmt(&self.0.0, f)
    }
}

impl PartialEq<u32> for NBitWord<u32> {
    fn eq(&self, other: &u32) -> bool {
        self.0.0 == *other
    }
}

impl<T> Shl for NBitWord<T>
where T: Shl<Output = T>
{
    type Output = Self;

    fn shl(self, rhs: Self) -> Self::Output {
        Self(Wrapping(self.0.0 << rhs.0.0))
    }
}

impl<T> Shr for NBitWord<T>
where T: Shr<Output = T>
{
    type Output = Self;

    fn shr(self, rhs: Self) -> Self::Output {
        Self(Wrapping(self.0.0 >> rhs.0.0))
    }
}

impl Sub<NBitWord<u32>> for u32
{
    type Output = NBitWord<u32>;

    fn sub(self, rhs: NBitWord<u32>) -> Self::Output {
        NBitWord(Wrapping(self - rhs.0.0))
    }
}

impl Sub<NBitWord<u64>> for u32 {
    type Output = NBitWord<u64>;

    fn sub(self, rhs: NBitWord<u64>) -> Self::Output {
        NBitWord(Wrapping(self as u64 - rhs.0.0))
    }
}

impl<T> UpperHex for NBitWord<T>
where T: UpperHex
{
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        UpperHex::fmt(&self.0.0, f)
    }
}
