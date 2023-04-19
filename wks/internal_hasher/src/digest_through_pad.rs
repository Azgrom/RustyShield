use crate::HashAlgorithm;

pub trait DigestThroughPad<H: HashAlgorithm> {
    fn finish(&mut self, state: &mut H);
    fn write(&mut self, state: &mut H, bytes: &[u8]);
}
