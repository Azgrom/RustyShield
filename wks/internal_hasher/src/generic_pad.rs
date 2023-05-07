use crate::{BigEndianBytes, BytePad, DigestThroughPad, HashAlgorithm, HasherPadOps, LenPad};
use core::ops::{Add, AddAssign, BitAnd, Index, IndexMut, Mul, Range, RangeFrom, RangeTo, Rem};

/// * `DELIMITER`: The delimiter byte used in the padding rule, which is unique to each specific application
///   of the sponge construction or finishing pad, when processing the SHA-1 family of hash algorithms.
#[derive(Clone, Debug, Eq, Hash, PartialEq, PartialOrd, Ord)]
pub struct GenericPad<S, const LEN: usize, const DELIMITER: u8>
where
    S: AddAssign<usize> + Clone + Copy + BitAnd<Output = usize> + From<usize> + Rem<Output = usize>,
{
    pub size: S,
    pub pad: [u8; LEN],
}

impl<S, const LEN: usize, const DELIMITER: u8> AsMut<[u8]> for GenericPad<S, LEN, DELIMITER>
where
    S: AddAssign<usize> + Clone + Copy + BitAnd<Output = usize> + From<usize> + Rem<Output = usize>,
{
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.pad
    }
}

impl<S, const LEN: usize, const DELIMITER: u8> AsRef<[u8]> for GenericPad<S, LEN, DELIMITER>
where
    S: AddAssign<usize> + Clone + Copy + BitAnd<Output = usize> + From<usize> + Rem<Output = usize>,
{
    fn as_ref(&self) -> &[u8] {
        &self.pad
    }
}

impl<S, const LEN: usize, const DELIMITER: u8> BytePad for GenericPad<S, LEN, DELIMITER>
where
    S: AddAssign<usize> + Clone + Copy + BitAnd<Output = usize> + From<usize> + Rem<Output = usize>,
{
    fn last_index(&self) -> usize {
        self.pad.len() - 1
    }

    fn offset(&self) -> usize {
        LEN * 7 / 8
    }
}

impl<S, const LEN: usize, const DELIMITER: u8> Default for GenericPad<S, LEN, DELIMITER>
where
    S: AddAssign<usize> + Copy + BitAnd<Output = usize> + From<usize> + Rem<Output = usize>
{
    fn default() -> Self {
        Self {
            size: S::from(0),
            pad: [0; LEN],
        }
    }
}

impl<S, const LEN: usize, const DELIMITER: u8> LenPad for GenericPad<S, LEN, DELIMITER>
where
    S: AddAssign<usize> + Copy + BitAnd<Output = usize> + From<usize> + Rem<Output = usize>
{
    fn len() -> usize {
        LEN
    }
}

impl<S, H, const LEN: usize, const DELIMITER: u8> DigestThroughPad<H> for GenericPad<S, LEN, DELIMITER>
where
    H: HashAlgorithm,
    S: Add<usize, Output = usize> + AddAssign<usize> + BigEndianBytes + BitAnd<Output = usize> + Clone + Copy + From<usize> + Mul<u32, Output = S> + Rem<Output = usize>,
{
    fn finish(&mut self, state: &mut H) {
        let trailing_byte = self.size.to_be_bytes();
        let zeros_pad = LEN - ((self.size + trailing_byte.as_ref().len()) % LEN);
        let mut offset = [0u8; LEN];
        offset[0] = DELIMITER;

        self.write(state, &offset[..zeros_pad]);
        self.write(state, trailing_byte.as_ref());
    }

    fn write(&mut self, state: &mut H, mut bytes: &[u8]) {
        let lw = self.size_mod_pad();
        self.size += bytes.len();

        if lw != 0 {
            let mut left = LEN - lw;
            if left > bytes.len() {
                left = bytes.len();
            }

            self.pad[lw..lw + left].clone_from_slice(&bytes[..left]);

            if (lw + left) % self.pad.len() != 0 {
                return;
            }

            state.hash_block(&self.pad);
            bytes = &bytes[left..];
        }

        while bytes.len() >= LEN {
            state.hash_block(&bytes[..LEN]);
            bytes = &bytes[LEN..];
        }

        if !bytes.is_empty() {
            self.pad[..bytes.len()].clone_from_slice(&bytes[..]);
        }
    }
}

impl<S, const LEN: usize, const DELIMITER: u8> HasherPadOps for GenericPad<S, LEN, DELIMITER>
    where
        S: Add<usize, Output = usize> + AddAssign<usize> + BitAnd<Output = usize> + Clone + Copy + From<usize> + Rem<Output = usize>,
{
    fn size_mod_pad(&self) -> usize {
        (self.size % self.pad.len().into()) as usize
    }

    fn zeros_pad(&self) -> usize {
        1 + (self.last_index() & (self.offset().wrapping_sub(self.size_mod_pad())))
    }
}

impl<S, const LEN: usize, const DELIMITER: u8> Index<usize> for GenericPad<S, LEN, DELIMITER>
where
    S: AddAssign<usize> + Clone + Copy + BitAnd<Output = usize> + From<usize> + Rem + Rem<Output = usize>,
{
    type Output = u8;

    fn index(&self, index: usize) -> &Self::Output {
        &self.pad[index]
    }
}

impl<S, const LEN: usize, const DELIMITER: u8> Index<Range<usize>> for GenericPad<S, LEN, DELIMITER>
where
    S: AddAssign<usize> + Clone + Copy + BitAnd<Output = usize> + From<usize> + Rem<Output = usize>,
{
    type Output = [u8];

    fn index(&self, range: Range<usize>) -> &Self::Output {
        &self.pad[range]
    }
}

impl<S, const LEN: usize, const DELIMITER: u8> Index<RangeFrom<usize>> for GenericPad<S, LEN, DELIMITER>
where
    S: AddAssign<usize> + Clone + Copy + BitAnd<Output = usize> + From<usize> + Rem<Output = usize>,
{
    type Output = [u8];

    fn index(&self, range_from: RangeFrom<usize>) -> &Self::Output {
        &self.pad[range_from]
    }
}

impl<S, const LEN: usize, const DELIMITER: u8> IndexMut<usize> for GenericPad<S, LEN, DELIMITER>
where
    S: AddAssign<usize> + Clone + Copy + BitAnd<Output = usize> + From<usize> + Rem<Output = usize>,
{
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.pad[index]
    }
}

impl<S, const LEN: usize, const DELIMITER: u8> IndexMut<Range<usize>> for GenericPad<S, LEN, DELIMITER>
where
    S: AddAssign<usize> + Clone + Copy + BitAnd<Output = usize> + From<usize> + Rem<Output = usize>,
{
    fn index_mut(&mut self, range: Range<usize>) -> &mut Self::Output {
        &mut self.pad[range]
    }
}

impl<S, const LEN: usize, const DELIMITER: u8> IndexMut<RangeFrom<usize>> for GenericPad<S, LEN, DELIMITER>
where
    S: AddAssign<usize> + Clone + Copy + BitAnd<Output = usize> + From<usize> + Rem<Output = usize>,
{
    fn index_mut(&mut self, range_from: RangeFrom<usize>) -> &mut Self::Output {
        &mut self.pad[range_from]
    }
}

impl<S, const LEN: usize, const DELIMITER: u8> Index<RangeTo<usize>> for GenericPad<S, LEN, DELIMITER>
where
    S: AddAssign<usize> + Clone + Copy + BitAnd<Output = usize> + From<usize> + Rem<Output = usize>,
{
    type Output = [u8];

    fn index(&self, range: RangeTo<usize>) -> &Self::Output {
        &self.pad[range]
    }
}

impl<S, const LEN: usize, const DELIMITER: u8> PartialEq<[u8; LEN]> for GenericPad<S, LEN, DELIMITER>
where
    S: AddAssign<usize> + Copy + BitAnd<Output = usize> + From<usize> + Rem<Output = usize>,
{
    fn eq(&self, other: &[u8; LEN]) -> bool {
        self.pad == *other
    }
}
