use crate::keccak::WIDTH;
use core::ops::{Index, IndexMut};
use core::slice::{Iter, IterMut};
use rs_n_bit_words::NBitWord;

#[derive(Clone, Copy, Default, Debug, Eq, Hash, PartialEq)]
pub(crate) struct Plane<T> {
    lanes: [NBitWord<T>; WIDTH],
}

impl<T> Index<usize> for Plane<T> {
    type Output = NBitWord<T>;

    fn index(&self, index: usize) -> &Self::Output {
        &self.lanes[index]
    }
}

impl<T> IndexMut<usize> for Plane<T> {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.lanes[index]
    }
}

impl<'a, T> IntoIterator for &'a Plane<T> {
    type Item = &'a NBitWord<T>;
    type IntoIter = Iter<'a, NBitWord<T>>;

    fn into_iter(self) -> Self::IntoIter {
        self.lanes.iter()
    }
}

impl<'a, T> IntoIterator for &'a mut Plane<T> {
    type Item = &'a mut NBitWord<T>;
    type IntoIter = IterMut<'a, NBitWord<T>>;

    fn into_iter(self) -> Self::IntoIter {
        self.lanes.iter_mut()
    }
}
