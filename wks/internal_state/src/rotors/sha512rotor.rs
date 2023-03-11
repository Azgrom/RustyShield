use n_bit_words_lib::{NBitWord, TSize};

type U64Word = NBitWord<u64>;

pub struct Sha512Rotor<'a, 'b>(
    pub U64Word,
    pub U64Word,
    pub U64Word,
    pub &'a mut U64Word,
    pub U64Word,
    pub U64Word,
    pub U64Word,
    pub &'b mut U64Word,
    pub U64Word,
);

impl Sha512Rotor<'_, '_> {
    pub(crate) fn rnd(&mut self, k: u64) {
        let t0 = self.4.sigma1() + U64Word::ch(self.4, self.5, self.6) + *self.7 + self.8 + k.into();
        *self.3 += t0;
        *self.7 = t0 + self.0.sigma0() + U64Word::maj(self.0, self.1, self.2);
    }
}
