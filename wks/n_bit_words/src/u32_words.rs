use core::{
    fmt::{Formatter, LowerHex, Result, UpperHex},
    hash::{Hash, Hasher},
    ops::{Add, AddAssign, BitAnd, BitOr, BitXor, Shr},
};

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

    pub fn gamma0(self) -> Self {
        self.rotate_right(7) ^ self.rotate_right(18) ^ (self >> 3)
    }

    pub fn gamma1(self) -> Self {
        self.rotate_right(17) ^ self.rotate_right(19) ^ (self >> 10)
    }

    pub fn sigma0(self) -> Self {
        self.rotate_right(2) ^ self.rotate_right(13) ^ self.rotate_right(22)
    }

    pub fn sigma1(self) -> Self {
        self.rotate_right(6) ^ self.rotate_right(11) ^ self.rotate_right(25)
    }

    pub fn from_be_bytes(bytes: [u8; 4]) -> Self {
        Self(u32::from_be_bytes(bytes))
    }

    pub fn to_be_bytes(&self) -> [u8; 4] {
        self.0.to_be_bytes()
    }
}

impl U32Word {
    // SHA-1 constants
    pub const T_00_19: u32 = 0x5A827999;
    pub const T_20_39: u32 = 0x6ED9EBA1;
    pub const T_40_59: u32 = 0x8F1BBCDC;
    pub const T_60_79: u32 = 0xCA62C1D6;

    // SHA-224 and SHA-256 constants
    pub const K00: u32 = 0x428A2F98;
    pub const K01: u32 = 0x71374491;
    pub const K02: u32 = 0xB5C0FBCF;
    pub const K03: u32 = 0xE9B5DBA5;
    pub const K04: u32 = 0x3956C25B;
    pub const K05: u32 = 0x59F111F1;
    pub const K06: u32 = 0x923F82A4;
    pub const K07: u32 = 0xAB1C5ED5;
    pub const K08: u32 = 0xD807AA98;
    pub const K09: u32 = 0x12835B01;
    pub const K10: u32 = 0x243185BE;
    pub const K11: u32 = 0x550C7DC3;
    pub const K12: u32 = 0x72BE5D74;
    pub const K13: u32 = 0x80DEB1FE;
    pub const K14: u32 = 0x9BDC06A7;
    pub const K15: u32 = 0xC19BF174;
    pub const K16: u32 = 0xE49B69C1;
    pub const K17: u32 = 0xEFBE4786;
    pub const K18: u32 = 0x0FC19DC6;
    pub const K19: u32 = 0x240CA1CC;
    pub const K20: u32 = 0x2DE92C6F;
    pub const K21: u32 = 0x4A7484AA;
    pub const K22: u32 = 0x5CB0A9DC;
    pub const K23: u32 = 0x76F988DA;
    pub const K24: u32 = 0x983E5152;
    pub const K25: u32 = 0xA831C66D;
    pub const K26: u32 = 0xB00327C8;
    pub const K27: u32 = 0xBF597FC7;
    pub const K28: u32 = 0xC6E00BF3;
    pub const K29: u32 = 0xD5A79147;
    pub const K30: u32 = 0x06CA6351;
    pub const K31: u32 = 0x14292967;
    pub const K32: u32 = 0x27B70A85;
    pub const K33: u32 = 0x2E1B2138;
    pub const K34: u32 = 0x4D2C6DFC;
    pub const K35: u32 = 0x53380D13;
    pub const K36: u32 = 0x650A7354;
    pub const K37: u32 = 0x766A0ABB;
    pub const K38: u32 = 0x81C2C92E;
    pub const K39: u32 = 0x92722C85;
    pub const K40: u32 = 0xA2BFE8A1;
    pub const K41: u32 = 0xA81A664B;
    pub const K42: u32 = 0xC24B8B70;
    pub const K43: u32 = 0xC76C51A3;
    pub const K44: u32 = 0xD192E819;
    pub const K45: u32 = 0xD6990624;
    pub const K46: u32 = 0xF40E3585;
    pub const K47: u32 = 0x106AA070;
    pub const K48: u32 = 0x19A4C116;
    pub const K49: u32 = 0x1E376C08;
    pub const K50: u32 = 0x2748774C;
    pub const K51: u32 = 0x34B0BCB5;
    pub const K52: u32 = 0x391C0CB3;
    pub const K53: u32 = 0x4ED8AA4A;
    pub const K54: u32 = 0x5B9CCA4F;
    pub const K55: u32 = 0x682E6FF3;
    pub const K56: u32 = 0x748F82EE;
    pub const K57: u32 = 0x78A5636F;
    pub const K58: u32 = 0x84C87814;
    pub const K59: u32 = 0x8CC70208;
    pub const K60: u32 = 0x90BEFFFA;
    pub const K61: u32 = 0xA4506CEB;
    pub const K62: u32 = 0xBEF9A3F7;
    pub const K63: u32 = 0xC67178F2;
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
