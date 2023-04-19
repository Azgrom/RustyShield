use crate::BytePad;

pub trait HasherPadOps: BytePad {
    fn size_mod_pad(&self) -> usize;
    fn zeros_pad(&self) -> usize {
        1 + (self.last_index() & (self.offset().wrapping_sub(self.size_mod_pad())))
    }
}
