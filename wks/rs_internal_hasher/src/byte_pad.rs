pub trait BytePad {
    fn last_index(&self) -> usize;
    fn offset(&self) -> usize;
}
