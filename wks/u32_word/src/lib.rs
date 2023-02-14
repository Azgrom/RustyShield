use core::ops::{Add, AddAssign};

#[derive(Clone, Copy, Hash)]
pub struct U32Word(u32);

impl U32Word {
    pub fn gamma0(self) -> u32 {
        self.0.rotate_right(7) ^ self.0.rotate_right(18) ^ (self.0 >> 3)
    }

    pub fn gamma1(self) -> Self {
        (self.0.rotate_right(17) ^ self.0.rotate_right(19) ^ (self.0 >> 10)).into()
    }
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

impl Default for U32Word {
    fn default() -> Self {
        Self(0)
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
