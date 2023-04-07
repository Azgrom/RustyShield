use crate::{BytePad, Size};

pub trait HasherOps: BytePad {
    fn size_mod_pad(&self) -> usize {
        Self::size(self) & Self::last_index(self)
    }
    fn zeros_pad(&self) -> usize {
        1 + (self.last_index() & (self.offset().wrapping_sub(self.size_mod_pad())))
    }
}
