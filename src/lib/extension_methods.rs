use core::ops::{RangeFrom, RangeTo};

pub trait ExtMethods {
    fn modulus_16_element(&self) -> usize;
    fn range_from(&self) -> RangeFrom<usize>;
    fn range_to(&self) -> RangeTo<usize>;
}

#[macro_export]
macro_rules! impl_ext_method {
    ($T:tt) => {
        impl ExtMethods for $T {
            fn modulus_16_element(&self) -> usize {
                (*self & 15) as usize
            }

            fn range_from(&self) -> RangeFrom<usize> {
                (*self as usize)..
            }

            fn range_to(&self) -> RangeTo<usize> {
                ..(*self as usize)
            }
        }
    };
}
