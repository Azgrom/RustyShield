use core::ops::{Index, IndexMut};
use n_bit_words_lib::NBitWord;

/// DWORDs struct that can later be expanded with SIMD to store 4 DWORDS in a single XMM register
#[derive(Clone, Debug, Hash, PartialEq)]
pub struct DWords<T>([NBitWord<T>; 16]);

type U32W = NBitWord<u32>;
type U64W = NBitWord<u64>;

impl From<&[u8; 64]> for DWords<u32> {
    fn from(value: &[u8; 64]) -> Self {
        Self([
            U32W::from([value[0], value[1], value[2], value[3]]),
            U32W::from([value[4], value[5], value[6], value[7]]),
            U32W::from([value[8], value[9], value[10], value[11]]),
            U32W::from([value[12], value[13], value[14], value[15]]),
            U32W::from([value[16], value[17], value[18], value[19]]),
            U32W::from([value[20], value[21], value[22], value[23]]),
            U32W::from([value[24], value[25], value[26], value[27]]),
            U32W::from([value[28], value[29], value[30], value[31]]),
            U32W::from([value[32], value[33], value[34], value[35]]),
            U32W::from([value[36], value[37], value[38], value[39]]),
            U32W::from([value[40], value[41], value[42], value[43]]),
            U32W::from([value[44], value[45], value[46], value[47]]),
            U32W::from([value[48], value[49], value[50], value[51]]),
            U32W::from([value[52], value[53], value[54], value[55]]),
            U32W::from([value[56], value[57], value[58], value[59]]),
            U32W::from([value[60], value[61], value[62], value[63]]),
        ])
    }
}

impl From<&[u8; 128]> for DWords<u64> {
    fn from(value: &[u8; 128]) -> Self {
        Self([
            U64W::from([value[0], value[1], value[2], value[3], value[4], value[5], value[6], value[7]]),
            U64W::from([value[8], value[9], value[10], value[11], value[12], value[13], value[14], value[15]]),
            U64W::from([value[16], value[17], value[18], value[19], value[20], value[21], value[22], value[23]]),
            U64W::from([value[24], value[25], value[26], value[27], value[28], value[29], value[30], value[31]]),
            U64W::from([value[32], value[33], value[34], value[35], value[36], value[37], value[38], value[39]]),
            U64W::from([value[40], value[41], value[42], value[43], value[44], value[45], value[46], value[47]]),
            U64W::from([value[48], value[49], value[50], value[51], value[52], value[53], value[54], value[55]]),
            U64W::from([value[56], value[57], value[58], value[59], value[60], value[61], value[62], value[63]]),
            U64W::from([value[64], value[65], value[66], value[67], value[68], value[69], value[70], value[71]]),
            U64W::from([value[72], value[73], value[74], value[75], value[76], value[77], value[78], value[79]]),
            U64W::from([value[80], value[81], value[82], value[83], value[84], value[85], value[86], value[87]]),
            U64W::from([value[88], value[89], value[90], value[91], value[92], value[93], value[94], value[95]]),
            U64W::from([value[96], value[97], value[98], value[99], value[100], value[101], value[102], value[103]]),
            U64W::from([
                value[104], value[105], value[106], value[107], value[108], value[109], value[110], value[111],
            ]),
            U64W::from([
                value[112], value[113], value[114], value[115], value[116], value[117], value[118], value[119],
            ]),
            U64W::from([
                value[120], value[121], value[122], value[123], value[124], value[125], value[126], value[127],
            ]),
        ])
    }
}

impl<T> Index<usize> for DWords<T> {
    type Output = NBitWord<T>;

    fn index(&self, index: usize) -> &Self::Output {
        &self.0[index]
    }
}

impl<T> IndexMut<usize> for DWords<T> {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.0[index]
    }
}
