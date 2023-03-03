use n_bit_words_lib::U64Word;

pub(crate) struct Sha384Comp<'a, 'b>(
    pub U64Word,
    pub U64Word,
    pub U64Word,
    pub &'a mut U64Word,
    pub U64Word,
    pub U64Word,
    pub U64Word,
    pub &'b mut U64Word,
);

impl Sha384Comp<'_, '_> {
    pub(crate) fn rnd(&mut self, w: U64Word, k: u64) {
        let t0 = *self.7 + self.4.sigma1() + U64Word::ch(self.4, self.5, self.6) + k + w;
        *self.3 += t0;
        *self.7 = t0 + self.0.sigma0() + U64Word::maj(self.0, self.1, self.2);
    }
}
