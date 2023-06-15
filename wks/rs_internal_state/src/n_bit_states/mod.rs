pub(crate) mod sha160bits_state;
pub(crate) mod sha256bits_state;
pub(crate) mod sha512bits_state;

pub trait GenericStateHasher {
    fn next_words(&mut self);
    fn block_00_15(&mut self);
    fn block_16_31(&mut self);
    fn block_32_47(&mut self);
    fn block_48_63(&mut self);
    fn block_64_79(&mut self);
}
