use crate::HasherWords;
use core::{hash::Hash, ops::AddAssign};

pub trait GenericStateHasher<T>: AddAssign + Clone + Hash {
    fn block_00_15(&mut self, w: &HasherWords<T>);
    fn block_16_31(&mut self, w: &mut HasherWords<T>);
    fn block_32_47(&mut self, w: &mut HasherWords<T>);
    fn block_48_63(&mut self, w: &mut HasherWords<T>);
    fn block_64_79(&mut self, w: &mut HasherWords<T>);
}
