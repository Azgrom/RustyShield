#![no_std]

pub use crate::rotate::Rotate;
pub use crate::t_size::TSize;
use core::{
    fmt::{Formatter, LowerHex, UpperHex},
    hash::{Hash, Hasher},
    num::Wrapping,
    ops::{Add, AddAssign, BitAnd, BitOr, BitXor, Shl, Shr, Sub},
};
use core::ops::{BitAndAssign, BitXorAssign, Not};

mod t_size;
mod rotate;

#[cfg(test)]
mod unit_tests;

/// Intel documentation provides that
/// `S0(a) = (a >>> 2) ^ (a >>> 13) ^ (a >>> 22)`
/// and `S1(e) = (e >>> 6) ^ (e >>> 11) ^ (e >>> 25)`
/// involves a number of register copy operations due to ror instructions
/// being destructive. And that number of register copies can be minimized
/// writing `S0` and `S1` as
/// `S0(a) = ((( a >>> 9) ^ a) >>> 11) ^ a) >>> 2`
/// and `S1(e) = (((e >>> 14) ^ e) >>> 5) ^ e) >>> 6`
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NBitWord<T>(Wrapping<T>);

impl Rotate for NBitWord<u8> {
    fn rotate_right(self, n: Self) -> Self {
        NBitWord(Wrapping(self.0 .0.rotate_right(n.0 .0 as u32)))
    }

    fn rotate_left(self, n: Self) -> Self {
        NBitWord(Wrapping(self.0 .0.rotate_left(n.0 .0 as u32)))
    }
}

impl Rotate for NBitWord<u16> {
    fn rotate_right(self, n: Self) -> Self {
        NBitWord(Wrapping(self.0 .0.rotate_right(n.0 .0 as u32)))
    }

    fn rotate_left(self, n: Self) -> Self {
        NBitWord(Wrapping(self.0 .0.rotate_left(n.0 .0 as u32)))
    }
}

impl Rotate for NBitWord<u32> {
    fn rotate_right(self, n: Self) -> Self {
        NBitWord(Wrapping(self.0 .0.rotate_right(n.0 .0)))
    }

    fn rotate_left(self, n: Self) -> Self {
        NBitWord(Wrapping(self.0 .0.rotate_left(n.0 .0)))
    }
}

impl Rotate for NBitWord<u64> {
    fn rotate_right(self, n: Self) -> Self {
        NBitWord(Wrapping(self.0 .0.rotate_right(n.0.0 as u32)))
    }

    fn rotate_left(self, n: Self) -> Self {
        NBitWord(Wrapping(self.0 .0.rotate_left(n.0.0 as u32)))
    }
}

impl TSize<u8> for NBitWord<u8> {
    const BITS: u32 = u8::BITS;
    const SIZE: usize = 1;

    fn gamma0(&self) -> Self {
        ((self.rotate_right(Self(Wrapping(3))) ^ *self) >> Self(Wrapping(1))) ^ self.rotate_right(Self(Wrapping(2)))
    }

    fn gamma1(&self) -> Self {
        ((((self.rotate_right(Self(Wrapping(5)))) ^ *self) >> Self(Wrapping(2))) ^ *self).rotate_right(Self(Wrapping(4)))
    }

    fn new(value: usize) -> u8 {
        value as u8
    }

    fn sigma0(&self) -> Self {
        (((self.rotate_right(Self(Wrapping(1)))) ^ self.rotate_right(Self(Wrapping(2))))) ^ self.rotate_right(Self(Wrapping(4)))
    }

    fn sigma1(&self) -> Self {
        (((self.rotate_right(Self(Wrapping(3)))) ^ self.rotate_right(Self(Wrapping(4))))) ^ self.rotate_right(Self(Wrapping(2)))
    }
}

impl TSize<u16> for NBitWord<u16> {
    const BITS: u32 = u8::BITS;
    const SIZE: usize = 2;

    fn gamma0(&self) -> Self {
        (((self.rotate_right(Self(Wrapping(5)))) ^ *self) >> Self(Wrapping(1)))
            ^ self.rotate_right(Self(Wrapping(2)))
    }

    fn gamma1(&self) -> Self {
        (((self.rotate_right(Self(Wrapping(9)))) ^ *self) >> Self(Wrapping(2)))
            ^ self.rotate_right(Self(Wrapping(6)))
    }

    fn new(value: usize) -> u16 {
        value as u16
    }

    fn sigma0(&self) -> Self {
        (((self.rotate_right(Self(Wrapping(1)))) ^ self.rotate_right(Self(Wrapping(4)))))
            ^ self.rotate_right(Self(Wrapping(8)))
    }

    fn sigma1(&self) -> Self {
        (((self.rotate_right(Self(Wrapping(5)))) ^ self.rotate_right(Self(Wrapping(7)))))
            ^ self.rotate_right(Self(Wrapping(4)))
    }
}

impl TSize<u32> for NBitWord<u32> {
    const BITS: u32 = u32::BITS;
    const SIZE: usize = 4;

    fn gamma0(&self) -> Self {
        self.rotate_right(Self(Wrapping(7))) ^ self.rotate_right(Self(Wrapping(18))) ^ (*self >> Self(Wrapping(3)))
    }

    fn gamma1(&self) -> Self {
        self.rotate_right(Self(Wrapping(17))) ^ self.rotate_right(Self(Wrapping(19))) ^ (*self >> Self(Wrapping(10)))
    }

    fn new(value: usize) -> u32 {
        value as u32
    }

    fn sigma0(&self) -> Self {
        ((((self.rotate_right(Self(Wrapping(9))))) ^ *self).rotate_right(Self(Wrapping(11))) ^ *self).rotate_right(Self(Wrapping(2)))
    }

    fn sigma1(&self) -> Self {
        ((((self.rotate_right(Self(Wrapping(14)))) ^ *self).rotate_right(Self(Wrapping(5)))) ^ *self).rotate_right(Self(Wrapping(6)))
    }
}

impl TSize<u64> for NBitWord<u64> {
    const BITS: u32 = u64::BITS;
    const SIZE: usize = 8;

    fn gamma0(&self) -> Self {
        self.rotate_right(Self(Wrapping(1))) ^ self.rotate_right(Self(Wrapping(8))) ^ (*self >> Self(Wrapping(7)))
    }

    fn gamma1(&self) -> Self {
        self.rotate_right(Self(Wrapping(19))) ^ self.rotate_right(Self(Wrapping(61))) ^ (*self >> Self(Wrapping(6)))
    }

    fn new(value: usize) -> u64 {
        value as u64
    }

    fn sigma0(&self) -> Self {
        self.rotate_right(Self(Wrapping(28)))
            ^ self.rotate_right(Self(Wrapping(34)))
            ^ self.rotate_right(Self(Wrapping(39)))
    }

    fn sigma1(&self) -> Self {
        self.rotate_right(Self(Wrapping(14)))
            ^ self.rotate_right(Self(Wrapping(18)))
            ^ self.rotate_right(Self(Wrapping(41)))
    }
}

impl<T> Add for NBitWord<T>
where
    Wrapping<T>: Add<Output = Wrapping<T>>,
{
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Self(self.0 + rhs.0)
    }
}

impl<T> Add<T> for NBitWord<T>
where
    Wrapping<T>: Add<Output = Wrapping<T>>,
{
    type Output = Self;

    fn add(self, rhs: T) -> Self::Output {
        Self(self.0 + Wrapping(rhs))
    }
}

impl Add<NBitWord<u32>> for u32
where
    Wrapping<u32>: Add<Output = Wrapping<u32>>,
{
    type Output = NBitWord<u32>;

    fn add(self, rhs: NBitWord<u32>) -> Self::Output {
        NBitWord(Wrapping(self) + rhs.0)
    }
}

impl<T> AddAssign for NBitWord<T>
where
    Wrapping<T>: AddAssign,
{
    fn add_assign(&mut self, rhs: Self) {
        self.0 += rhs.0
    }
}

impl<T> BitAnd for NBitWord<T>
where
    T: BitAnd<Output = T>,
{
    type Output = Self;

    fn bitand(self, rhs: Self) -> Self::Output {
        Self(Wrapping(self.0 .0 & rhs.0 .0))
    }
}

impl<T> BitAndAssign for NBitWord<T>
where
T: BitAndAssign
{
    fn bitand_assign(&mut self, rhs: Self) {
        self.0.0.bitand_assign(rhs.0.0)
    }
}

impl<T> BitOr for NBitWord<T>
where
    T: BitOr<Output = T>,
{
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        Self(Wrapping(self.0 .0 | rhs.0 .0))
    }
}

impl BitOr<NBitWord<u8>> for u8 {
    type Output = NBitWord<u8>;

    fn bitor(self, rhs: NBitWord<u8>) -> Self::Output {
        NBitWord(Wrapping(self | rhs.0.0))
    }
}

impl BitOr<NBitWord<u16>> for u16 {
    type Output = NBitWord<u16>;

    fn bitor(self, rhs: NBitWord<u16>) -> Self::Output {
        NBitWord(Wrapping(self | rhs.0.0))
    }
}

impl BitOr<NBitWord<u32>> for u32 {
    type Output = NBitWord<u32>;

    fn bitor(self, rhs: NBitWord<u32>) -> Self::Output {
        NBitWord(Wrapping(self | rhs.0.0))
    }
}

impl BitOr<NBitWord<u64>> for u64 {
    type Output = NBitWord<u64>;

    fn bitor(self, rhs: NBitWord<u64>) -> Self::Output {
        NBitWord(Wrapping(self | rhs.0.0))
    }
}

impl<T> BitXor for NBitWord<T>
where
    T: BitXor<Output = T>,
{
    type Output = Self;

    fn bitxor(self, rhs: Self) -> Self::Output {
        Self(Wrapping(self.0 .0 ^ rhs.0 .0))
    }
}

impl<T> BitXorAssign for NBitWord<T>
where
T: BitXorAssign
{
    fn bitxor_assign(&mut self, rhs: Self) {
        self.0.0.bitxor_assign(rhs.0.0)
    }
}

impl<T: Default> Default for NBitWord<T> {
    fn default() -> Self {
        Self(Wrapping(T::default()))
    }
}

impl<T> From<T> for NBitWord<T> {
    fn from(value: T) -> Self {
        Self(Wrapping(value))
    }
}

impl From<NBitWord<u32>> for u32 {
    fn from(value: NBitWord<u32>) -> Self {
        value.0 .0
    }
}

impl From<NBitWord<u64>> for u32 {
    fn from(value: NBitWord<u64>) -> Self {
        (value.0 .0 >> 32) as u32
    }
}

impl From<[u8; 4]> for NBitWord<u32> {
    fn from(value: [u8; 4]) -> Self {
        u32::from_be_bytes([value[0], value[1], value[2], value[3]]).into()
    }
}

impl From<NBitWord<u32>> for u64 {
    fn from(value: NBitWord<u32>) -> Self {
        value.0 .0 as u64
    }
}

impl From<NBitWord<u64>> for u64 {
    fn from(value: NBitWord<u64>) -> Self {
        value.0 .0
    }
}

impl From<[u8; 8]> for NBitWord<u64> {
    fn from(value: [u8; 8]) -> Self {
        u64::from_be_bytes([value[0], value[1], value[2], value[3], value[4], value[5], value[6], value[7]]).into()
    }
}

impl<T> Hash for NBitWord<T>
where
    T: Hash,
{
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0 .0.hash(state)
    }
}

impl<T> LowerHex for NBitWord<T>
where
    T: LowerHex,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        LowerHex::fmt(&self.0 .0, f)
    }
}

impl<T> Not for NBitWord<T>
where T: Not<Output = T>
{
    type Output = Self;

    fn not(self) -> Self::Output {
        Self(Wrapping(!self.0 .0))
    }
}

impl PartialEq<u32> for NBitWord<u32> {
    fn eq(&self, other: &u32) -> bool {
        self.0 .0 == *other
    }
}

impl<T> Shl for NBitWord<T>
where
    T: Shl<Output = T>,
{
    type Output = Self;

    fn shl(self, rhs: Self) -> Self::Output {
        Self(Wrapping(self.0 .0 << rhs.0 .0))
    }
}

impl Shl<u32> for NBitWord<u8> {
    type Output = u8;

    fn shl(self, rhs: u32) -> Self::Output {
        self.0.0 << rhs
    }
}

impl Shl<u32> for NBitWord<u16> {
    type Output = u16;

    fn shl(self, rhs: u32) -> Self::Output {
        self.0.0 << rhs
    }
}

impl Shl<u32> for NBitWord<u32> {
    type Output = u32;

    fn shl(self, rhs: u32) -> Self::Output {
        self.0.0 << rhs
    }
}

impl Shl<u32> for NBitWord<u64> {
    type Output = u64;

    fn shl(self, rhs: u32) -> Self::Output {
        self.0.0 << rhs
    }
}

impl<T> Shr for NBitWord<T>
where
    T: Shr<Output = T>,
{
    type Output = Self;

    fn shr(self, rhs: Self) -> Self::Output {
        Self(Wrapping(self.0 .0 >> rhs.0 .0))
    }
}

impl Shr<u32> for NBitWord<u8> {
    type Output = NBitWord<u8>;

    fn shr(self, rhs: u32) -> Self::Output {
        Self(Wrapping(self.0 .0 >> rhs))
    }
}

impl Shr<u32> for NBitWord<u16> {
    type Output = NBitWord<u16>;

    fn shr(self, rhs: u32) -> Self::Output {
        Self(Wrapping(self.0 .0 >> rhs))
    }
}

impl Shr<u32> for NBitWord<u32> {
    type Output = NBitWord<u32>;

    fn shr(self, rhs: u32) -> Self::Output {
        Self(Wrapping(self.0 .0 >> rhs))
    }
}

impl Shr<u32> for NBitWord<u64> {
    type Output = NBitWord<u64>;

    fn shr(self, rhs: u32) -> Self::Output {
        Self(Wrapping(self.0 .0 >> rhs))
    }
}

impl Sub<NBitWord<u8>> for u32 {
    type Output = NBitWord<u8>;

    fn sub(self, rhs: NBitWord<u8>) -> Self::Output {
        NBitWord(Wrapping((self - rhs.0 .0 as u32) as u8))
    }
}

impl Sub<NBitWord<u16>> for u32 {
    type Output = NBitWord<u16>;

    fn sub(self, rhs: NBitWord<u16>) -> Self::Output {
        NBitWord(Wrapping((self - rhs.0 .0 as u32) as u16))
    }
}

impl Sub<NBitWord<u32>> for u32 {
    type Output = NBitWord<u32>;

    fn sub(self, rhs: NBitWord<u32>) -> Self::Output {
        NBitWord(Wrapping(self - rhs.0 .0))
    }
}

impl Sub<NBitWord<u64>> for u32 {
    type Output = NBitWord<u64>;

    fn sub(self, rhs: NBitWord<u64>) -> Self::Output {
        NBitWord(Wrapping(self as u64 - rhs.0 .0))
    }
}

impl<T> UpperHex for NBitWord<T>
where
    T: UpperHex,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        UpperHex::fmt(&self.0 .0, f)
    }
}
