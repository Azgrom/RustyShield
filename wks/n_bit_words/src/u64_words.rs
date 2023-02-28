use core::{
    fmt::{Formatter, LowerHex, Result, UpperHex},
    hash::{Hash, Hasher},
    ops::{Add, AddAssign, BitAnd, BitOr, BitXor, Shr}
};

#[derive(Clone, Copy, Debug)]
pub struct U64Word(u64);

impl U64Word {
    #[inline(always)]
    pub fn ch(x: U64Word, y: U64Word, z: U64Word) -> Self {
        ((y ^ z) & x) ^ z
    }

    #[inline(always)]
    pub fn parity(x: U64Word, y: U64Word, z: U64Word) -> Self {
        x ^ y ^ z
    }

    #[inline(always)]
    pub fn maj(x: U64Word, y: U64Word, z: U64Word) -> Self {
        (x & y) | ((x | y) & z)
    }

    pub fn rotate_left(&self, n: u32) -> Self {
        Self(self.0.rotate_left(n))
    }

    pub fn rotate_right(&self, n: u32) -> Self {
        Self(self.0.rotate_right(n))
    }

    pub fn gamma0(self) -> Self {
        self.rotate_right(1) ^ self.rotate_right(8) ^ (self >> 7)
    }

    pub fn gamma1(self) -> Self {
        self.rotate_right(19) ^ self.rotate_right(61) ^ (self >> 6)
    }

    pub fn sigma0(self) -> Self {
        self.rotate_right(28) ^ self.rotate_right(34) ^ self.rotate_right(39)
    }

    pub fn sigma1(self) -> Self {
        self.rotate_right(14) ^ self.rotate_right(18) ^ self.rotate_right(41)
    }

    pub fn from_be_bytes(bytes: [u8; 8]) -> Self {
        Self(u64::from_be_bytes(bytes))
    }

    pub fn to_be_bytes(&self) -> [u8; 8] {
        self.0.to_be_bytes()
    }
}

impl U64Word {
    // SHA-384, SHA-512, SHA-512/224, SHA-512/256 constants
    pub const K00: u64 = 0x428A2F98D728AE22;
    pub const K01: u64 = 0x7137449123EF65CD;
    pub const K02: u64 = 0xB5C0FBCFEC4D3B2F;
    pub const K03: u64 = 0xE9B5DBA58189DBBC;
    pub const K04: u64 = 0x3956C25BF348B538;
    pub const K05: u64 = 0x59F111F1B605D019;
    pub const K06: u64 = 0x923F82A4AF194F9B;
    pub const K07: u64 = 0xAB1C5ED5DA6D8118;
    pub const K08: u64 = 0xD807AA98A3030242;
    pub const K09: u64 = 0x12835B0145706FBE;
    pub const K10: u64 = 0x243185BE4EE4B28C;
    pub const K11: u64 = 0x550C7DC3D5FFB4E2;
    pub const K12: u64 = 0x72BE5D74F27B896F;
    pub const K13: u64 = 0x80DEB1FE3B1696B1;
    pub const K14: u64 = 0x9BDC06A725C71235;
    pub const K15: u64 = 0xC19BF174CF692694;
    pub const K16: u64 = 0xE49B69C19EF14AD2;
    pub const K17: u64 = 0xEFBE4786384F25E3;
    pub const K18: u64 = 0x0FC19DC68B8CD5B5;
    pub const K19: u64 = 0x240CA1CC77AC9C65;
    pub const K20: u64 = 0x2DE92C6F592B0275;
    pub const K21: u64 = 0x4A7484AA6EA6E483;
    pub const K22: u64 = 0x5CB0A9DCBD41FBD4;
    pub const K23: u64 = 0x76F988DA831153B5;
    pub const K24: u64 = 0x983E5152EE66DFAB;
    pub const K25: u64 = 0xA831C66D2DB43210;
    pub const K26: u64 = 0xB00327C898FB213F;
    pub const K27: u64 = 0xBF597FC7BEEF0EE4;
    pub const K28: u64 = 0xC6E00BF33DA88FC2;
    pub const K29: u64 = 0xD5A79147930AA725;
    pub const K30: u64 = 0x06CA6351E003826F;
    pub const K31: u64 = 0x142929670A0E6E70;
    pub const K32: u64 = 0x27B70A8546D22FFC;
    pub const K33: u64 = 0x2E1B21385C26C926;
    pub const K34: u64 = 0x4D2C6DFC5AC42AED;
    pub const K35: u64 = 0x53380D139D95B3DF;
    pub const K36: u64 = 0x650A73548BAF63DE;
    pub const K37: u64 = 0x766A0ABB3C77B2A8;
    pub const K38: u64 = 0x81C2C92E47EDAEE6;
    pub const K39: u64 = 0x92722C851482353B;
    pub const K40: u64 = 0xA2BFE8A14CF10364;
    pub const K41: u64 = 0xA81A664BBC423001;
    pub const K42: u64 = 0xC24B8B70D0F89791;
    pub const K43: u64 = 0xC76C51A30654BE30;
    pub const K44: u64 = 0xD192E819D6EF5218;
    pub const K45: u64 = 0xD69906245565A910;
    pub const K46: u64 = 0xF40E35855771202A;
    pub const K47: u64 = 0x106AA07032BBD1B8;
    pub const K48: u64 = 0x19A4C116B8D2D0C8;
    pub const K49: u64 = 0x1E376C085141AB53;
    pub const K50: u64 = 0x2748774CDF8EEB99;
    pub const K51: u64 = 0x34B0BCB5E19B48A8;
    pub const K52: u64 = 0x391C0CB3C5C95A63;
    pub const K53: u64 = 0x4ED8AA4AE3418ACB;
    pub const K54: u64 = 0x5B9CCA4F7763E373;
    pub const K55: u64 = 0x682E6FF3D6B2B8A3;
    pub const K56: u64 = 0x748F82EE5DEFB2FC;
    pub const K57: u64 = 0x78A5636F43172F60;
    pub const K58: u64 = 0x84C87814A1F0AB72;
    pub const K59: u64 = 0x8CC702081A6439EC;
    pub const K60: u64 = 0x90BEFFFA23631E28;
    pub const K61: u64 = 0xA4506CEBDE82BDE9;
    pub const K62: u64 = 0xBEF9A3F7B2C67915;
    pub const K63: u64 = 0xC67178F2E372532B;
    pub const K64: u64 = 0xCA273ECEEA26619C;
    pub const K65: u64 = 0xD186B8C721C0C207;
    pub const K66: u64 = 0xEADA7DD6CDE0EB1E;
    pub const K67: u64 = 0xF57D4F7FEE6ED178;
    pub const K68: u64 = 0x06F067AA72176FBA;
    pub const K69: u64 = 0x0A637DC5A2C898A6;
    pub const K70: u64 = 0x113F9804BEF90DAE;
    pub const K71: u64 = 0x1B710B35131C471B;
    pub const K72: u64 = 0x28DB77F523047D84;
    pub const K73: u64 = 0x32CAAB7B40C72493;
    pub const K74: u64 = 0x3C9EBE0A15C9BEBC;
    pub const K75: u64 = 0x431D67C49C100D4C;
    pub const K76: u64 = 0x4CC5D4BECB3E42B6;
    pub const K77: u64 = 0x597F299CFC657E2A;
    pub const K78: u64 = 0x5FCB6FAB3AD6FAEC;
    pub const K79: u64 = 0x6C44198C4A475817;
}

impl Add for U64Word {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Self(self.0.wrapping_add(rhs.0))
    }
}

impl Add<u64> for U64Word {
    type Output = Self;

    fn add(self, rhs: u64) -> Self::Output {
        Self(self.0.wrapping_add(rhs))
    }
}

impl Add<U64Word> for u64 {
    type Output = U64Word;

    fn add(self, rhs: U64Word) -> Self::Output {
        U64Word(self.wrapping_add(rhs.0))
    }
}

impl AddAssign for U64Word {
    fn add_assign(&mut self, rhs: Self) {
        *self = *self + rhs;
    }
}

impl BitAnd for U64Word {
    type Output = Self;

    fn bitand(self, rhs: Self) -> Self::Output {
        Self(self.0 & rhs.0)
    }
}

impl BitOr for U64Word {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        Self(self.0 | rhs.0)
    }
}

impl BitXor for U64Word {
    type Output = Self;

    fn bitxor(self, rhs: Self) -> Self::Output {
        Self(self.0 ^ rhs.0)
    }
}

impl Default for U64Word {
    fn default() -> Self {
        Self(u64::MIN)
    }
}

impl LowerHex for U64Word {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        LowerHex::fmt(&self.0, f)
    }
}

impl UpperHex for U64Word {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        UpperHex::fmt(&self.0, f)
    }
}

impl From<u64> for U64Word {
    fn from(value: u64) -> Self {
        Self(value)
    }
}

impl From<U64Word> for u64 {
    fn from(value: U64Word) -> Self {
        value.0
    }
}

impl Hash for U64Word {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.hash(state)
    }
}

impl PartialEq for U64Word {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl PartialEq<u64> for U64Word {
    fn eq(&self, other: &u64) -> bool {
        self.0 == *other
    }
}

impl Shr<u8> for U64Word {
    type Output = Self;

    fn shr(self, rhs: u8) -> Self::Output {
        Self(self.0 >> rhs)
    }
}
