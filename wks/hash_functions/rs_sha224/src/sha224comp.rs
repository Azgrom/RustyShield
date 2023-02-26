use n_bit_words_lib::U32Word;

pub(crate) struct Sha224Comp<'a, 'b>(
    pub(crate) U32Word,
    pub(crate) U32Word,
    pub(crate) U32Word,
    pub(crate) &'a mut U32Word,
    pub(crate) U32Word,
    pub(crate) U32Word,
    pub(crate) U32Word,
    pub(crate) &'b mut U32Word,
);

impl Sha224Comp<'_, '_> {
    pub fn rnd(&mut self, w: U32Word, k: u32) {
        let t0 = *self.7 + self.4.sigma1() + U32Word::ch(self.4, self.5, self.6) + k + w;
        *self.3 += t0;
        *self.7 = t0 + self.0.sigma0() + U32Word::maj(self.0, self.1, self.2);
    }
}
