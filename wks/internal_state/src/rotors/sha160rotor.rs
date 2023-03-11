use n_bit_words_lib::{NBitWord, TSize};

type U32Word = NBitWord<u32>;

pub struct Sha160Rotor<'a, 'b>(
    pub U32Word,
    pub &'a mut U32Word,
    pub U32Word,
    pub U32Word,
    pub &'b mut U32Word,
    pub U32Word,
);

impl Sha160Rotor<'_, '_> {
    pub const T_00_19: u32 = 0x5A827999;
    pub const T_20_39: u32 = 0x6ED9EBA1;
    pub const T_40_59: u32 = 0x8F1BBCDC;
    pub const T_60_79: u32 = 0xCA62C1D6;
}

impl Sha160Rotor<'_, '_> {
    pub fn rounds_00_19(&mut self) {
        *self.4 += self.5 + Self::T_00_19.into() + self.0.rotate_left(5.into()) + U32Word::ch(*self.1, self.2, self.3);
        *self.1 = self.1.rotate_right(2.into());
    }

    pub fn rounds_20_39(&mut self) {
        *self.4 += self.5 + Self::T_20_39.into() + self.0.rotate_left(5.into()) + U32Word::parity(*self.1, self.2, self.3);
        *self.1 = self.1.rotate_right(2.into());
    }

    pub fn rounds_40_59(&mut self) {
        *self.4 += self.5 + Self::T_40_59.into() + self.0.rotate_left(5.into()) + U32Word::maj(*self.1, self.2, self.3);
        *self.1 = self.1.rotate_right(2.into());
    }

    pub fn rounds_60_79(&mut self) {
        *self.4 += self.5 + Self::T_60_79.into() + self.0.rotate_left(5.into()) + U32Word::parity(*self.1, self.2, self.3);
        *self.1 = self.1.rotate_right(2.into());
    }
}
