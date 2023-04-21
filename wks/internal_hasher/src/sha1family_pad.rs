use crate::{BigEndianBytes, BytePad, DigestThroughPad, HashAlgorithm, HasherPadOps, LenPad};
use core::ops::{AddAssign, BitAnd, Index, IndexMut, Mul, Range, RangeFrom, RangeTo};

#[derive(Clone, Debug, Eq, Hash, PartialEq, PartialOrd, Ord)]
pub struct Sha1FamilyPad<S, const LEN: usize>
where
    S: AddAssign<usize> + Clone + Copy + BitAnd<Output = usize> + From<usize>,
{
    pub size: S,
    pub pad: [u8; LEN],
}

impl<S, const LEN: usize> AsMut<[u8]> for Sha1FamilyPad<S, LEN>
where
    S: AddAssign<usize> + Clone + Copy + BitAnd<Output = usize> + From<usize>,
{
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.pad
    }
}

impl<S, const LEN: usize> AsRef<[u8]> for Sha1FamilyPad<S, LEN>
where
    S: AddAssign<usize> + Clone + Copy + BitAnd<Output = usize> + From<usize>,
{
    fn as_ref(&self) -> &[u8] {
        &self.pad
    }
}

impl<S, const LEN: usize> BytePad for Sha1FamilyPad<S, LEN>
where
    S: AddAssign<usize> + Clone + Copy + BitAnd<Output = usize> + From<usize>,
{
    fn last_index(&self) -> usize {
        self.pad.len() - 1
    }

    fn offset(&self) -> usize {
        self.pad.len() * 7 / 8 - 1
    }
}

impl<S, const LEN: usize> Default for Sha1FamilyPad<S, LEN>
where
    S: AddAssign<usize> + Copy + BitAnd<Output = usize> + From<usize>,
{
    fn default() -> Self {
        Self {
            size: S::from(0),
            pad: [0; LEN],
        }
    }
}

impl<S, const LEN: usize> LenPad for Sha1FamilyPad<S, LEN>
where
    S: AddAssign<usize> + Copy + BitAnd<Output = usize> + From<usize>,
{
    fn len() -> usize {
        LEN
    }
}

impl<S, const LEN: usize> HasherPadOps for Sha1FamilyPad<S, LEN>
where
    S: AddAssign<usize> + Clone + Copy + BitAnd<Output = usize> + From<usize>,
{
    fn size_mod_pad(&self) -> usize {
        (self.size & self.last_index().into()) as usize
    }
}

impl<S, H, const LEN: usize> DigestThroughPad<H> for Sha1FamilyPad<S, LEN>
where
    H: HashAlgorithm,
    S: AddAssign<usize> + BigEndianBytes + BitAnd<Output = usize> + Clone + Copy + From<usize> + Mul<u32, Output = S>,
{
    fn finish(&mut self, state: &mut H) {
        let zeros_pad = self.zeros_pad();
        let mut offset = [0u8; LEN];
        offset[0] = 0x80;

        let len = (self.size * 8u32).to_be_bytes();
        self.write(state, &offset[..zeros_pad]);
        self.write(state, len.as_ref());
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

            if (lw + left) & self.last_index() != 0 {
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

impl<S, const LEN: usize> Index<usize> for Sha1FamilyPad<S, LEN>
where
    S: AddAssign<usize> + Clone + Copy + BitAnd<Output = usize> + From<usize>,
{
    type Output = u8;

    fn index(&self, index: usize) -> &Self::Output {
        &self.pad[index]
    }
}

impl<S, const LEN: usize> Index<Range<usize>> for Sha1FamilyPad<S, LEN>
where
    S: AddAssign<usize> + Clone + Copy + BitAnd<Output = usize> + From<usize>,
{
    type Output = [u8];

    fn index(&self, range: Range<usize>) -> &Self::Output {
        &self.pad[range]
    }
}

impl<S, const LEN: usize> Index<RangeFrom<usize>> for Sha1FamilyPad<S, LEN>
where
    S: AddAssign<usize> + Clone + Copy + BitAnd<Output = usize> + From<usize>,
{
    type Output = [u8];

    fn index(&self, range_from: RangeFrom<usize>) -> &Self::Output {
        &self.pad[range_from]
    }
}

impl<S, const LEN: usize> IndexMut<usize> for Sha1FamilyPad<S, LEN>
where
    S: AddAssign<usize> + Clone + Copy + BitAnd<Output = usize> + From<usize>,
{
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.pad[index]
    }
}

impl<S, const LEN: usize> IndexMut<Range<usize>> for Sha1FamilyPad<S, LEN>
where
    S: AddAssign<usize> + Clone + Copy + BitAnd<Output = usize> + From<usize>,
{
    fn index_mut(&mut self, range: Range<usize>) -> &mut Self::Output {
        &mut self.pad[range]
    }
}

impl<S, const LEN: usize> IndexMut<RangeFrom<usize>> for Sha1FamilyPad<S, LEN>
where
    S: AddAssign<usize> + Clone + Copy + BitAnd<Output = usize> + From<usize>,
{
    fn index_mut(&mut self, range_from: RangeFrom<usize>) -> &mut Self::Output {
        &mut self.pad[range_from]
    }
}

impl<S, const LEN: usize> Index<RangeTo<usize>> for Sha1FamilyPad<S, LEN>
where
    S: AddAssign<usize> + Clone + Copy + BitAnd<Output = usize> + From<usize>,
{
    type Output = [u8];

    fn index(&self, range: RangeTo<usize>) -> &Self::Output {
        &self.pad[range]
    }
}

impl<S, const LEN: usize> PartialEq<[u8; LEN]> for Sha1FamilyPad<S, LEN>
where
    S: AddAssign<usize> + Copy + BitAnd<Output = usize> + From<usize>,
{
    fn eq(&self, other: &[u8; LEN]) -> bool {
        self.pad == *other
    }
}
