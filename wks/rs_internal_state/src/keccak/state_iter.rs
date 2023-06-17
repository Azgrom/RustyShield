use crate::keccak::plane::Plane;
use crate::keccak::plane_iter::PlaneIter;
use crate::KeccakState;
use core::iter::{FlatMap, Flatten};
use core::slice::{Iter, IterMut};
use rs_n_bit_words::NBitWord;

type PlaneArrayIntoLaneArrayFlatMap<'a, T> =
    FlatMap<Iter<'a, Plane<T>>, PlaneIter<'a, T>, for<'b> fn(&'a Plane<T>) -> PlaneIter<'a, T>>;

pub(crate) struct KeccakStateIter<'a, T> {
    iter: PlaneArrayIntoLaneArrayFlatMap<'a, T>,
}

impl<'a, T: Default + Copy> KeccakStateIter<'a, T> {
    pub(crate) fn new(src: &'a KeccakState<T>) -> Self {
        let x = |plane| PlaneIter::new(plane);
        Self {
            iter: src.planes.iter().flat_map(x),
        }
    }
}

impl<'a, T> ExactSizeIterator for KeccakStateIter<'a, T> {}

impl<'a, T> Iterator for KeccakStateIter<'a, T> {
    type Item = &'a NBitWord<T>;

    fn next(&mut self) -> Option<Self::Item> {
        self.iter.next()
    }
}

pub struct KeccakStateIterMut<'a, T> {
    iter: Flatten<IterMut<'a, Plane<T>>>,
}

impl<'a, T: Default + Copy> KeccakStateIterMut<'a, T> {
    pub(crate) fn new(src: &'a mut KeccakState<T>) -> Self {
        Self {
            iter: src.planes.iter_mut().flatten(),
        }
    }
}

impl<'a, T> ExactSizeIterator for KeccakStateIterMut<'a, T> {}

impl<'a, T> Iterator for KeccakStateIterMut<'a, T> {
    type Item = &'a mut NBitWord<T>;

    fn next(&mut self) -> Option<Self::Item> {
        self.iter.next()
    }
}
