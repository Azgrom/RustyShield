pub trait HasherPadOps {
    fn size_mod_pad(&self) -> usize;
    fn zeros_pad(&self) -> usize;
}
