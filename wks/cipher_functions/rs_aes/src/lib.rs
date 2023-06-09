#![no_std]

use core::ops::{Add, AddAssign, BitAnd, BitXor, Mul, Shl, Shr};
use rs_n_bit_words::NBitWord;

/// `GF2ToThe8` represents a Galois Field with 2^8 (256) elements.
///
/// A Galois Field, named after the mathematician Évariste Galois, is a field in which
/// there are a finite number of elements. In this case, the field has 2^8 or 256 elements.
///
/// This struct is used to represent elements of this field, and is primarily used in
/// applications where finite field arithmetic is required, such as error detection and
/// correction codes, cryptography, and other areas of discrete mathematics.
///
/// The `GF2ToThe8` struct uses an `NBitWord<u8>` internally to store its value, providing
/// the necessary wraparound behavior for arithmetic operations in this field.
///
/// Arithmetic operations for `GF2ToThe8` elements are defined to follow the properties of
/// Galois Field arithmetic, with addition corresponding to the XOR operation and multiplication
/// being more complex, usually involving look-up tables or polynomial multiplication.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GF2ToThe8(NBitWord<u8>);

impl GF2ToThe8 {
    fn x_times(&self) -> Self {
        if *self & 0x80 != 0 {
            (*self << 1) ^ 0x1B
        } else {
            *self << 1
        }
    }
}

impl Add for GF2ToThe8 {
    type Output = Self;

    #[allow(clippy::suspicious_arithmetic_impl)]
    fn add(self, rhs: Self) -> Self::Output {
        GF2ToThe8(self.0 ^ rhs.0)
    }
}

impl AddAssign for GF2ToThe8 {
    fn add_assign(&mut self, rhs: Self) {
        *self = *self + rhs
    }
}

impl BitAnd<u8> for GF2ToThe8 {
    type Output = Self;

    fn bitand(self, rhs: u8) -> Self::Output {
        Self(self.0 & rhs.into())
    }
}

impl BitXor<u8> for GF2ToThe8 {
    type Output = Self;

    fn bitxor(self, rhs: u8) -> Self::Output {
        Self(self.0 ^ rhs)
    }
}

impl From<u8> for GF2ToThe8 {
    fn from(value: u8) -> Self {
        Self(value.into())
    }
}

impl Mul for GF2ToThe8 {
    type Output = Self;

    fn mul(mut self, mut rhs: Self) -> Self::Output {
        let mut product = GF2ToThe8::from(0);
        if self == 0u8 || rhs == 0u8 {
            return product;
        }

        for _ in 0..8 {
            if rhs.0 & NBitWord::from(1u8) == 1u8 {
                product += self;
            }
            self = self.x_times();
            rhs = GF2ToThe8(rhs.0 >> 1u8);
        }

        product
    }
}

impl PartialEq<u8> for GF2ToThe8 {
    fn eq(&self, other: &u8) -> bool {
        self.0 == *other
    }
}

impl Shl<u8> for GF2ToThe8 {
    type Output = Self;

    fn shl(self, rhs: u8) -> Self::Output {
        Self(self.0 << rhs)
    }
}

impl Shr<u8> for GF2ToThe8 {
    type Output = Self;

    fn shr(self, rhs: u8) -> Self::Output {
        Self(self.0 >> rhs)
    }
}

#[cfg(test)]
mod unit_tests {
    use super::*;

    #[test]
    fn test_addition_closure() {
        let a = GF2ToThe8::from(10u8);
        let b = GF2ToThe8::from(20u8);

        let sum = a + b;

        assert!(matches!(sum, GF2ToThe8(_)));
    }

    #[test]
    fn test_addition_commutativity() {
        let a = GF2ToThe8::from(10u8);
        let b = GF2ToThe8::from(20u8);

        let sum1 = a + b;
        let sum2 = b + a;

        assert_eq!(sum1, sum2);
    }

    #[test]
    fn test_addition_associativity() {
        let a = GF2ToThe8::from(10u8);
        let b = GF2ToThe8::from(20u8);
        let c = GF2ToThe8::from(30u8);

        let sum1 = (a + b) + c;
        let sum2 = a + (b + c);

        assert_eq!(sum1, sum2);
    }

    #[test]
    fn test_addition_identity() {
        let a = GF2ToThe8::from(10u8);
        let zero = GF2ToThe8::from(0u8);

        assert_eq!(a + zero, a);
    }

    #[test]
    fn test_multiplication_closure() {
        let a = GF2ToThe8::from(10u8);
        let b = GF2ToThe8::from(20u8);

        let product = a * b;

        assert!(matches!(product, GF2ToThe8(_)));
    }

    #[test]
    fn test_multiplication_commutativity() {
        let a = GF2ToThe8::from(10u8);
        let b = GF2ToThe8::from(20u8);

        let product1 = a * b;
        let product2 = b * a;

        assert_eq!(product1, product2);
    }

    #[test]
    fn test_multiplication_associativity() {
        let a = GF2ToThe8::from(10u8);
        let b = GF2ToThe8::from(20u8);
        let c = GF2ToThe8::from(30u8);

        let product1 = (a * b) * c;
        let product2 = a * (b * c);

        assert_eq!(product1, product2);
    }

    #[test]
    fn test_multiplication_identity() {
        let a = GF2ToThe8::from(10u8);
        let one = GF2ToThe8::from(1u8);

        assert_eq!(a * one, a);
    }

    #[test]
    fn test_distributivity() {
        let a = GF2ToThe8::from(10u8);
        let b = GF2ToThe8::from(20u8);
        let c = GF2ToThe8::from(30u8);

        let left = a * (b + c);
        let right = (a * b) + (a * c);

        assert_eq!(left, right);
    }

    #[test]
    fn test_multiplication() {
        let x = GF2ToThe8::from(0x57);

        assert_eq!(x * GF2ToThe8::from(0x01), x);
        assert_eq!(x * GF2ToThe8::from(0x02), GF2ToThe8::from(0xAE));
        assert_eq!(x * GF2ToThe8::from(0x04), GF2ToThe8::from(0x47));
        assert_eq!(x * GF2ToThe8::from(0x08), GF2ToThe8::from(0x8E));
        assert_eq!(x * GF2ToThe8::from(0x10), GF2ToThe8::from(0x07));
        assert_eq!(x * GF2ToThe8::from(0x20), GF2ToThe8::from(0x0E));
        assert_eq!(x * GF2ToThe8::from(0x40), GF2ToThe8::from(0x1C));
        assert_eq!(x * GF2ToThe8::from(0x80), GF2ToThe8::from(0x38));
    }

    #[test]
    fn compound_primitive_multiplication_of_57_times_13() {
        let x = GF2ToThe8::from(0x57);
        let y = GF2ToThe8::from(0x13);

        // x * y by the distributive property be equivalent of x * (1 ^ 2 ^ 10)
        assert_eq!(x * y, x * (GF2ToThe8::from(0x01) + GF2ToThe8::from(0x02) + GF2ToThe8::from(0x10)));
        assert_eq!(x * y, GF2ToThe8::from(0x57) + GF2ToThe8::from(0xAE) + GF2ToThe8::from(0x07));
        assert_eq!(x * y, GF2ToThe8::from(0xFE));
    }
}
