use core::fmt::{LowerHex, UpperHex};
use core::hash::{BuildHasher, Hash};
use core::ops::AddAssign;
use crate::HasherWords;

pub trait GenericStateHasher<T>: AddAssign + BuildHasher + Clone + Default + Hash + LowerHex + UpperHex{
    fn block_00_15(&mut self, w: &HasherWords<T>);
    fn block_16_31(&mut self, w: &mut HasherWords<T>);
    fn block_32_47(&mut self, w: &mut HasherWords<T>);
    fn block_48_63(&mut self, w: &mut HasherWords<T>);
    fn block_64_79(&mut self, w: &mut HasherWords<T>);
}
