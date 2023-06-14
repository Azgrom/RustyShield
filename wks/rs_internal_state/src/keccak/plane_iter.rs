use core::slice::Iter;
use rs_n_bit_words::NBitWord;
use crate::keccak::plane::Plane;

pub(crate) struct PlaneIter<'a, T> {
    iter: Iter<'a, NBitWord<T>>
}

impl<'a, T> PlaneIter<'a, T> {
    pub(crate) fn new(src: &'a Plane<T>) -> Self {
        Self {
            iter: src.lanes.iter()
        }
    }
}

impl<'a, T> ExactSizeIterator for PlaneIter<'a, T> {}

impl<'a, T> Iterator for PlaneIter<'a, T> {
    type Item = &'a NBitWord<T>;

    fn next(&mut self) -> Option<Self::Item> {
        self.iter.next()
    }
}
