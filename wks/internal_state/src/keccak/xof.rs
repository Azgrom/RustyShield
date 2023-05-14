pub trait ExtendedOutputFunction<const OUTPUT_SIZE: usize> {
    fn squeeze_u64(&self) -> u64;
    /// Squeezes the output data from the sponge
    fn squeeze(&mut self) -> [u8; OUTPUT_SIZE];
}
