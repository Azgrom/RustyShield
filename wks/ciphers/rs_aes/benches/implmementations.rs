use std::ops::{Add, AddAssign, Mul};
use n_bit_words_lib::NBitWord;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FirstImplementationOfGF2ToThe8(NBitWord<u8>);

impl Add for FirstImplementationOfGF2ToThe8 {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        FirstImplementationOfGF2ToThe8(self.0 ^ rhs.0)
    }
}

impl From<u8> for FirstImplementationOfGF2ToThe8 {
    fn from(value: u8) -> Self {
        Self(value.into())
    }
}

impl Mul for FirstImplementationOfGF2ToThe8 {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        let lhs_val: u8 = self.0.into();
        let rhs_val: u8 = rhs.0.into();

        let mut a = lhs_val;
        let mut b = rhs_val;
        let mut product: u16 = 0;

        for _ in 0..8 {
            if b & 1 != 0 {
                product ^= a as u16;
            }
            let high_bit_set = a & 0x80;
            a <<= 1;
            if high_bit_set != 0 {
                a ^= 0x1B; /* x^8 + x^4 + x^3 + x + 1 */
            }
            b >>= 1;
        }

        // Apply the modulo operation with the irreducible polynomial
        // if the product exceeds the field's order.
        if product >= 0x100 {
            product ^= 0x11B;
        }

        FirstImplementationOfGF2ToThe8::from(product as u8)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SecondImplementationOfGF2ToThe8(NBitWord<u8>);

impl SecondImplementationOfGF2ToThe8 {
    fn x_times(&self) -> Self {
        let val: u8 = self.0.into();
        if val & 0x80 != 0 {
            SecondImplementationOfGF2ToThe8::from((val << 1) ^ 0x1B)
        } else {
            SecondImplementationOfGF2ToThe8::from(val << 1)
        }
    }
}

impl Add for SecondImplementationOfGF2ToThe8 {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        SecondImplementationOfGF2ToThe8(self.0 ^ rhs.0)
    }
}

impl AddAssign for SecondImplementationOfGF2ToThe8 {
    fn add_assign(&mut self, rhs: Self) {
        *self = *self + rhs
    }
}

impl From<u8> for SecondImplementationOfGF2ToThe8 {
    fn from(value: u8) -> Self {
        Self(value.into())
    }
}

impl Mul for SecondImplementationOfGF2ToThe8 {
    type Output = Self;

    fn mul(mut self, mut rhs: Self) -> Self::Output {
        let mut product = SecondImplementationOfGF2ToThe8::from(0);
        if self == 0u8 || rhs == 0u8 {
            return product;
        }

        for _ in 0..8 {
            if rhs.0 & NBitWord::from(1u8) == 1u8 {
                product += self;
            }
            self = self.x_times();
            rhs = SecondImplementationOfGF2ToThe8(rhs.0 >> 1u8);
        }

        product
    }
}

impl PartialEq<u8> for SecondImplementationOfGF2ToThe8 {
    fn eq(&self, other: &u8) -> bool {
        self.0 == *other
    }
}
