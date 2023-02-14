use crate::{
    sha1_hasher::Sha1Hasher, H0, H1, H2, H3, H4, SHA1_BLOCK_SIZE, SHA_CBLOCK_LAST_INDEX,
    SHA_OFFSET_PAD,
};
use core::hash::Hasher;

#[cfg(feature = "nightly")]
use core::{
    arch::x86_64::{
        _mm_sha1msg1_epu32, _mm_sha1msg2_epu32, _mm_sha1nexte_epu32, _mm_sha1rnds4_epu32,
    },
    simd::Simd,
};

const MESSAGE: &str = "abc";

fn instantiate_and_preprocess_abc_message() -> Sha1Hasher {
    let mut hasher = Sha1Hasher::default();
    Hasher::write(&mut hasher, MESSAGE.as_ref());
    let zero_padding_length = Sha1Hasher::zero_padding_length(&hasher);
    let mut offset_pad: [u8; SHA_OFFSET_PAD as usize] = [0u8; SHA_OFFSET_PAD as usize];
    let pad_len: [u8; 8] = (hasher.size * 8).to_be_bytes();

    offset_pad[0] = 0x80;
    offset_pad[zero_padding_length - 8..zero_padding_length].clone_from_slice(&pad_len);
    hasher
}

fn completed_words(hasher: &mut Sha1Hasher) {
    let pad_len: [u8; 8] = (MESSAGE.len() * 8).to_be_bytes();
    let zero_padding_len = hasher.zero_padding_length();
    let mut offset_pad: [u8; SHA_OFFSET_PAD as usize] = [0u8; SHA_OFFSET_PAD as usize];
    offset_pad[0] = 0x80;
    offset_pad[zero_padding_len - 8..zero_padding_len].clone_from_slice(&pad_len);

    let len_w = (hasher.size & SHA_CBLOCK_LAST_INDEX as u64) as u8;
    let left = (SHA1_BLOCK_SIZE - len_w as u32) as u8;
    hasher.words[(len_w as usize)..(len_w + left) as usize]
        .clone_from_slice(&offset_pad[..zero_padding_len]);
}

#[test]
fn start_processing_rounds_integrity() {
    let mut hasher = Sha1Hasher::default();
    Hasher::write(&mut hasher, MESSAGE.as_ref());

    let expected_rounds_of_words_1: [u8; SHA1_BLOCK_SIZE as usize] =
        [vec![0x61, 0x62, 0x63, 0x00], vec![0u8; 60]]
            .concat()
            .try_into()
            .unwrap();
    assert_eq!(hasher.words, expected_rounds_of_words_1);

    completed_words(&mut hasher);

    let expected_rounds_of_words_2: [u8; SHA1_BLOCK_SIZE as usize] =
        [vec![0x61, 0x62, 0x63, 0x80], vec![0u8; 59], vec![0x18]]
            .concat()
            .try_into()
            .unwrap();
    assert_eq!(hasher.words, expected_rounds_of_words_2);
}

#[test]
fn test() {
    let simd = Simd::from_array([H0, H1, H2, H3]);
    let h0_u128 = (H0 as u128) << 96;
    let h1_u128 = (H1 as u128) << 64;
    let h2_u128 = (H2 as u128) << 32;
    let h3_u128 = (H3 as u128);
    let h0h1h2h3_u128 = h0_u128 | h1_u128 | h2_u128 | h3_u128;
    // unsafe { let i = _mm_sha1msg1_epu32(h0h1h2h3_u128, 0);
    // }
    // _mm_sha1msg2_epu32()
    // _mm_sha1nexte_epu32()
    // _mm_sha1rnds4_epu32()
}

#[test]
fn assert_hash_values_integrity_for_each_step_00_to_15() {
    let mut hasher = instantiate_and_preprocess_abc_message();
    let [mut a, mut b, mut c, mut d, mut e] = hasher.state.to_slice().clone();
    let mut d_words: [u32; 16] = [0; 16];
    completed_words(&mut hasher);
    hasher.u32_words_from_u8_pad(&mut d_words);

    assert_eq!([a, b, c, d, e], [H0, H1, H2, H3, H4]);

    Sha1Hasher::rounds_00_15(a, &mut b, c, d, &mut e, d_words[0]);
    assert_eq!(
        [e, a, b, c, d],
        [0x0116FC33, 0x67452301, 0x7BF36AE2, 0x98BADCFE, 0x10325476]
    );

    Sha1Hasher::rounds_00_15(e, &mut a, b, c, &mut d, d_words[1]);
    assert_eq!(
        [d, e, a, b, c],
        [0x8990536D, 0x0116FC33, 0x59D148C0, 0x7BF36AE2, 0x98BADCFE]
    );

    Sha1Hasher::rounds_00_15(d, &mut e, a, b, &mut c, d_words[2]);
    assert_eq!(
        [c, d, e, a, b],
        [0xA1390F08, 0x8990536D, 0xC045BF0C, 0x59D148C0, 0x7BF36AE2]
    );

    Sha1Hasher::rounds_00_15(c, &mut d, e, a, &mut b, d_words[3]);
    assert_eq!(
        [b, c, d, e, a],
        [0xCDD8E11B, 0xA1390F08, 0x626414DB, 0xC045BF0C, 0x59D148C0]
    );

    Sha1Hasher::rounds_00_15(b, &mut c, d, e, &mut a, d_words[4]);
    assert_eq!(
        [a, b, c, d, e],
        [0xCFD499DE, 0xCDD8E11B, 0x284E43C2, 0x626414DB, 0xC045BF0C]
    );

    Sha1Hasher::rounds_00_15(a, &mut b, c, d, &mut e, d_words[5]);
    assert_eq!(
        [e, a, b, c, d],
        [0x3FC7CA40, 0xCFD499DE, 0xF3763846, 0x284E43C2, 0x626414DB]
    );

    Sha1Hasher::rounds_00_15(e, &mut a, b, c, &mut d, d_words[6]);
    assert_eq!(
        [d, e, a, b, c],
        [0x993E30C1, 0x3FC7CA40, 0xB3F52677, 0xF3763846, 0x284E43C2]
    );

    Sha1Hasher::rounds_00_15(d, &mut e, a, b, &mut c, d_words[7]);
    assert_eq!(
        [c, d, e, a, b],
        [0x9E8C07D4, 0x993E30C1, 0x0FF1F290, 0xB3F52677, 0xF3763846]
    );

    Sha1Hasher::rounds_00_15(c, &mut d, e, a, &mut b, d_words[8]);
    assert_eq!(
        [b, c, d, e, a],
        [0x4B6AE328, 0x9E8C07D4, 0x664F8C30, 0x0FF1F290, 0xB3F52677]
    );

    Sha1Hasher::rounds_00_15(b, &mut c, d, e, &mut a, d_words[9]);
    assert_eq!(
        [a, b, c, d, e],
        [0x8351F929, 0x4B6AE328, 0x27A301F5, 0x664F8C30, 0xFF1F290]
    );

    Sha1Hasher::rounds_00_15(a, &mut b, c, d, &mut e, d_words[10]);
    assert_eq!(
        [e, a, b, c, d],
        [0xFBDA9E89, 0x8351F929, 0x12DAB8CA, 0x27A301F5, 0x664F8C30]
    );

    Sha1Hasher::rounds_00_15(e, &mut a, b, c, &mut d, d_words[11]);
    assert_eq!(
        [d, e, a, b, c],
        [0x63188FE4, 0xFBDA9E89, 0x60D47E4A, 0x12DAB8CA, 0x27A301F5]
    );

    Sha1Hasher::rounds_00_15(d, &mut e, a, b, &mut c, d_words[12]);
    assert_eq!(
        [c, d, e, a, b],
        [0x4607B664, 0x63188FE4, 0x7EF6A7A2, 0x60D47E4A, 0x12DAB8CA]
    );

    Sha1Hasher::rounds_00_15(c, &mut d, e, a, &mut b, d_words[13]);
    assert_eq!(
        [b, c, d, e, a],
        [0x9128F695, 0x4607B664, 0x18C623F9, 0x7EF6A7A2, 0x60D47E4A]
    );

    Sha1Hasher::rounds_00_15(b, &mut c, d, e, &mut a, d_words[14]);
    assert_eq!(
        [a, b, c, d, e],
        [0x196BEE77, 0x9128F695, 0x1181ED99, 0x18C623F9, 0x7EF6A7A2]
    );

    Sha1Hasher::rounds_00_15(a, &mut b, c, d, &mut e, d_words[15]);
    assert_eq!(
        [e, a, b, c, d],
        [0x20BDD62F, 0x196BEE77, 0x644A3DA5, 0x1181ED99, 0x18C623F9]
    );
}

#[test]
fn assert_hash_values_integrity_for_each_step_16_to_19() {
    let mut hasher = instantiate_and_preprocess_abc_message();
    let [mut a, mut b, mut c, mut d, mut e] = hasher.state.to_slice().clone();
    let mut d_words: [u32; 16] = [0; 16];
    completed_words(&mut hasher);
    hasher.u32_words_from_u8_pad(&mut d_words);

    Sha1Hasher::rounds_00_15(a, &mut b, c, d, &mut e, d_words[0]);
    Sha1Hasher::rounds_00_15(e, &mut a, b, c, &mut d, d_words[1]);
    Sha1Hasher::rounds_00_15(d, &mut e, a, b, &mut c, d_words[2]);
    Sha1Hasher::rounds_00_15(c, &mut d, e, a, &mut b, d_words[3]);
    Sha1Hasher::rounds_00_15(b, &mut c, d, e, &mut a, d_words[4]);
    Sha1Hasher::rounds_00_15(a, &mut b, c, d, &mut e, d_words[5]);
    Sha1Hasher::rounds_00_15(e, &mut a, b, c, &mut d, d_words[6]);
    Sha1Hasher::rounds_00_15(d, &mut e, a, b, &mut c, d_words[7]);
    Sha1Hasher::rounds_00_15(c, &mut d, e, a, &mut b, d_words[8]);
    Sha1Hasher::rounds_00_15(b, &mut c, d, e, &mut a, d_words[9]);
    Sha1Hasher::rounds_00_15(a, &mut b, c, d, &mut e, d_words[10]);
    Sha1Hasher::rounds_00_15(e, &mut a, b, c, &mut d, d_words[11]);
    Sha1Hasher::rounds_00_15(d, &mut e, a, b, &mut c, d_words[12]);
    Sha1Hasher::rounds_00_15(c, &mut d, e, a, &mut b, d_words[13]);
    Sha1Hasher::rounds_00_15(b, &mut c, d, e, &mut a, d_words[14]);
    Sha1Hasher::rounds_00_15(a, &mut b, c, d, &mut e, d_words[15]);

    d_words[0] = (d_words[0] ^ d_words[2] ^ d_words[8] ^ d_words[13]).rotate_left(1);
    d_words[1] = (d_words[1] ^ d_words[3] ^ d_words[9] ^ d_words[14]).rotate_left(1);
    d_words[2] = (d_words[2] ^ d_words[4] ^ d_words[10] ^ d_words[15]).rotate_left(1);
    d_words[3] = (d_words[3] ^ d_words[5] ^ d_words[11] ^ d_words[0]).rotate_left(1);

    Sha1Hasher::rounds_16_19(e, &mut a, b, c, &mut d, d_words[0]);
    assert_eq!(
        [d, e, a, b, c],
        [0x4E925823, 0x20BDD62F, 0xC65AFB9D, 0x644A3DA5, 0x1181ED99]
    );

    Sha1Hasher::rounds_16_19(d, &mut e, a, b, &mut c, d_words[1]);
    assert_eq!(
        [c, d, e, a, b],
        [0x82AA6728, 0x4E925823, 0xC82F758B, 0xC65AFB9D, 0x644A3DA5]
    );

    Sha1Hasher::rounds_16_19(c, &mut d, e, a, &mut b, d_words[2]);
    assert_eq!(
        [b, c, d, e, a],
        [0xDC64901D, 0x82AA6728, 0xD3A49608, 0xC82F758B, 0xC65AFB9D]
    );

    Sha1Hasher::rounds_16_19(b, &mut c, d, e, &mut a, d_words[3]);
    assert_eq!(
        [a, b, c, d, e],
        [0xFD9E1D7D, 0xDC64901D, 0x20AA99CA, 0xD3A49608, 0xC82F758B]
    );
}

#[test]
fn assert_hash_values_integrity_for_each_step_20_to_39() {
    let mut hasher = instantiate_and_preprocess_abc_message();
    let [mut a, mut b, mut c, mut d, mut e] = hasher.state.to_slice().clone();
    let mut d_words: [u32; 16] = [0; 16];
    completed_words(&mut hasher);
    hasher.u32_words_from_u8_pad(&mut d_words);

    Sha1Hasher::rounds_00_15(a, &mut b, c, d, &mut e, d_words[0]);
    Sha1Hasher::rounds_00_15(e, &mut a, b, c, &mut d, d_words[1]);
    Sha1Hasher::rounds_00_15(d, &mut e, a, b, &mut c, d_words[2]);
    Sha1Hasher::rounds_00_15(c, &mut d, e, a, &mut b, d_words[3]);
    Sha1Hasher::rounds_00_15(b, &mut c, d, e, &mut a, d_words[4]);
    Sha1Hasher::rounds_00_15(a, &mut b, c, d, &mut e, d_words[5]);
    Sha1Hasher::rounds_00_15(e, &mut a, b, c, &mut d, d_words[6]);
    Sha1Hasher::rounds_00_15(d, &mut e, a, b, &mut c, d_words[7]);
    Sha1Hasher::rounds_00_15(c, &mut d, e, a, &mut b, d_words[8]);
    Sha1Hasher::rounds_00_15(b, &mut c, d, e, &mut a, d_words[9]);
    Sha1Hasher::rounds_00_15(a, &mut b, c, d, &mut e, d_words[10]);
    Sha1Hasher::rounds_00_15(e, &mut a, b, c, &mut d, d_words[11]);
    Sha1Hasher::rounds_00_15(d, &mut e, a, b, &mut c, d_words[12]);
    Sha1Hasher::rounds_00_15(c, &mut d, e, a, &mut b, d_words[13]);
    Sha1Hasher::rounds_00_15(b, &mut c, d, e, &mut a, d_words[14]);
    Sha1Hasher::rounds_00_15(a, &mut b, c, d, &mut e, d_words[15]);

    d_words[0] = (d_words[0] ^ d_words[2] ^ d_words[8] ^ d_words[13]).rotate_left(1);
    d_words[1] = (d_words[1] ^ d_words[3] ^ d_words[9] ^ d_words[14]).rotate_left(1);
    d_words[2] = (d_words[2] ^ d_words[4] ^ d_words[10] ^ d_words[15]).rotate_left(1);
    d_words[3] = (d_words[3] ^ d_words[5] ^ d_words[11] ^ d_words[0]).rotate_left(1);

    Sha1Hasher::rounds_16_19(e, &mut a, b, c, &mut d, d_words[0]);
    Sha1Hasher::rounds_16_19(d, &mut e, a, b, &mut c, d_words[1]);
    Sha1Hasher::rounds_16_19(c, &mut d, e, a, &mut b, d_words[2]);
    Sha1Hasher::rounds_16_19(b, &mut c, d, e, &mut a, d_words[3]);

    d_words[4] = (d_words[4] ^ d_words[6] ^ d_words[12] ^ d_words[1]).rotate_left(1);
    d_words[5] = (d_words[5] ^ d_words[7] ^ d_words[13] ^ d_words[2]).rotate_left(1);
    d_words[6] = (d_words[6] ^ d_words[8] ^ d_words[14] ^ d_words[3]).rotate_left(1);
    d_words[7] = (d_words[7] ^ d_words[9] ^ d_words[15] ^ d_words[4]).rotate_left(1);
    let step_20th_word = d_words[4];
    let step_21th_word = d_words[5];
    let step_22th_word = d_words[6];
    let step_23th_word = d_words[7];
    d_words[8] = (d_words[8] ^ d_words[10] ^ d_words[0] ^ d_words[5]).rotate_left(1);
    d_words[9] = (d_words[9] ^ d_words[11] ^ d_words[1] ^ d_words[6]).rotate_left(1);
    d_words[10] = (d_words[10] ^ d_words[12] ^ d_words[2] ^ d_words[7]).rotate_left(1);
    d_words[11] = (d_words[11] ^ d_words[13] ^ d_words[3] ^ d_words[8]).rotate_left(1);
    d_words[12] = (d_words[12] ^ d_words[14] ^ d_words[4] ^ d_words[9]).rotate_left(1);
    d_words[13] = (d_words[13] ^ d_words[15] ^ d_words[5] ^ d_words[10]).rotate_left(1);
    d_words[14] = (d_words[14] ^ d_words[0] ^ d_words[6] ^ d_words[11]).rotate_left(1);
    d_words[15] = (d_words[15] ^ d_words[1] ^ d_words[7] ^ d_words[12]).rotate_left(1);
    d_words[0] = (d_words[0] ^ d_words[2] ^ d_words[8] ^ d_words[13]).rotate_left(1);
    d_words[1] = (d_words[1] ^ d_words[3] ^ d_words[9] ^ d_words[14]).rotate_left(1);
    d_words[2] = (d_words[2] ^ d_words[4] ^ d_words[10] ^ d_words[15]).rotate_left(1);
    d_words[3] = (d_words[3] ^ d_words[5] ^ d_words[11] ^ d_words[0]).rotate_left(1);
    d_words[4] = (d_words[4] ^ d_words[6] ^ d_words[12] ^ d_words[1]).rotate_left(1);
    d_words[5] = (d_words[5] ^ d_words[7] ^ d_words[13] ^ d_words[2]).rotate_left(1);
    d_words[6] = (d_words[6] ^ d_words[8] ^ d_words[14] ^ d_words[3]).rotate_left(1);
    d_words[7] = (d_words[7] ^ d_words[9] ^ d_words[15] ^ d_words[4]).rotate_left(1);

    Sha1Hasher::rounds_20_39(a, &mut b, c, d, &mut e, step_20th_word);
    assert_eq!(
        [e, a, b, c, d],
        [0x1A37B0CA, 0xFD9E1D7D, 0x77192407, 0x20AA99CA, 0xD3A49608]
    );

    Sha1Hasher::rounds_20_39(e, &mut a, b, c, &mut d, step_21th_word);
    assert_eq!(
        [d, e, a, b, c],
        [0x33A23BFC, 0x1A37B0CA, 0x7F67875F, 0x77192407, 0x20AA99CA]
    );

    Sha1Hasher::rounds_20_39(d, &mut e, a, b, &mut c, step_22th_word);
    assert_eq!(
        [c, d, e, a, b],
        [0x21283486, 0x33A23BFC, 0x868DEC32, 0x7F67875F, 0x77192407]
    );

    Sha1Hasher::rounds_20_39(c, &mut d, e, a, &mut b, step_23th_word);
    assert_eq!(
        [b, c, d, e, a],
        [0xD541F12D, 0x21283486, 0x0CE88EFF, 0x868DEC32, 0x7F67875F]
    );

    Sha1Hasher::rounds_20_39(b, &mut c, d, e, &mut a, d_words[8]);
    assert_eq!(
        [a, b, c, d, e],
        [0xC7567DC6, 0xD541F12D, 0x884A0D21, 0x0CE88EFF, 0x868DEC32]
    );

    Sha1Hasher::rounds_20_39(a, &mut b, c, d, &mut e, d_words[9]);
    assert_eq!(
        [e, a, b, c, d],
        [0x48413BA4, 0xC7567DC6, 0x75507C4B, 0x884A0D21, 0x0CE88EFF]
    );

    Sha1Hasher::rounds_20_39(e, &mut a, b, c, &mut d, d_words[10]);
    assert_eq!(
        [d, e, a, b, c],
        [0xBE35FBD5, 0x48413BA4, 0xB1D59F71, 0x75507C4B, 0x884A0D21]
    );

    Sha1Hasher::rounds_20_39(d, &mut e, a, b, &mut c, d_words[11]);
}
