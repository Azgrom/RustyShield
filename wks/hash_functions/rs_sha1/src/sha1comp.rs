use n_bit_words_lib::U32Word;

pub struct Sha1Comp<'a, 'b>(
    pub U32Word,
    pub &'a mut U32Word,
    pub U32Word,
    pub U32Word,
    pub &'b mut U32Word,
    pub U32Word,
);

impl Sha1Comp<'_, '_> {
    pub(crate) fn rounds_00_19(&mut self) {
        *self.4 += self.5 + U32Word::T_00_19 + self.0.rotate_left(5) + U32Word::ch(*self.1, self.2, self.3);
        *self.1 = self.1.rotate_right(2);
    }

    pub(crate) fn rounds_20_39(&mut self) {
        *self.4 += self.5 + U32Word::T_20_39 + self.0.rotate_left(5) + U32Word::parity(*self.1, self.2, self.3);
        *self.1 = self.1.rotate_right(2);
    }

    pub(crate) fn rounds_40_59(&mut self) {
        *self.4 += self.5 + U32Word::T_40_59 + self.0.rotate_left(5) + U32Word::maj(*self.1, self.2, self.3);
        *self.1 = self.1.rotate_right(2);
    }

    pub(crate) fn rounds_60_79(&mut self) {
        *self.4 += self.5 + U32Word::T_60_79 + self.0.rotate_left(5) + U32Word::parity(*self.1, self.2, self.3);
        *self.1 = self.1.rotate_right(2);
    }
}
