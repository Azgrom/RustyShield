extern crate alloc;
use crate::{
    sha1hasher::Sha1Hasher,
    sha1state::{H0, H1, H2, H3, H4},
};
use alloc::vec;
use core::hash::Hasher;
use internal_state::{Sha160BitsState, Sha160Rotor as Sha160};

#[cfg(feature = "nightly")]
use core::{
    arch::x86_64::{_mm_sha1msg1_epu32, _mm_sha1msg2_epu32, _mm_sha1nexte_epu32, _mm_sha1rnds4_epu32},
    simd::Simd,
};
use hash_ctx_lib::{BlockHasher, GenericStateHasher, HasherWords};

const MESSAGE: &str = "abc";

fn instantiate_and_preprocess_abc_message() -> Sha1Hasher {
    let mut hasher = Sha1Hasher::default();
    Hasher::write(&mut hasher, MESSAGE.as_ref());
    let zero_padding_length = Sha1Hasher::zeros_pad_length(&hasher) as usize;
    let pad_len: [u8; 8] = (hasher.size * 8).to_be_bytes();
    let mut offset_pad: [u8; Sha1Hasher::U8_PAD_SIZE as usize] = [0u8; Sha1Hasher::U8_PAD_SIZE as usize];
    offset_pad[0] = 0x80;

    Hasher::write(&mut hasher, &offset_pad[..zero_padding_length]);
    hasher.padding[56..].clone_from_slice(&pad_len);

    hasher
}

fn completed_words(hasher: &mut Sha1Hasher) {
    let zero_padding_len = Sha1Hasher::zeros_pad_length(hasher) as usize;
    let mut offset_pad: [u8; Sha1Hasher::U8_PAD_SIZE as usize] = [0u8; Sha1Hasher::U8_PAD_SIZE as usize];
    offset_pad[0] = 0x80;

    let mut len_w = hasher.size as usize & Sha1Hasher::U8_PAD_LAST_INDEX as usize;
    let mut left = Sha1Hasher::U8_PAD_SIZE as usize - len_w;
    hasher.padding[len_w..len_w + left].clone_from_slice(&offset_pad[..left]);
    hasher.size += zero_padding_len as u64;

    let pad_len: [u8; 8] = ((MESSAGE.len() as u64) * 8).to_be_bytes();
    len_w = hasher.size as usize & Sha1Hasher::U8_PAD_LAST_INDEX as usize;
    left = Sha1Hasher::U8_PAD_SIZE as usize - len_w;
    hasher.padding[len_w..len_w + left].clone_from_slice(&pad_len);
    hasher.size += zero_padding_len as u64;
}

#[test]
fn start_processing_rounds_integrity() {
    let mut hasher = Sha1Hasher::default();
    Hasher::write(&mut hasher, MESSAGE.as_ref());

    let expected_rounds_of_words_1: [u8; Sha1Hasher::U8_PAD_SIZE as usize] =
        [vec![0x61, 0x62, 0x63, 0x00], vec![0u8; 60]].concat().try_into().unwrap();
    assert_eq!(hasher.padding, expected_rounds_of_words_1);

    completed_words(&mut hasher);

    let expected_rounds_of_words_2: [u8; Sha1Hasher::U8_PAD_SIZE as usize] =
        [vec![0x61, 0x62, 0x63, 0x80], vec![0u8; 59], vec![0x18]].concat().try_into().unwrap();
    assert_eq!(hasher.padding, expected_rounds_of_words_2);
}

// #[test]
// fn test() {
//     let simd = Simd::from_array([H0, H1, H2, H3]);
//     let h0_u128 = (H0 as u128) << 96;
//     let h1_u128 = (H1 as u128) << 64;
//     let h2_u128 = (H2 as u128) << 32;
//     let h3_u128 = (H3 as u128);
//     let h0h1h2h3_u128 = h0_u128 | h1_u128 | h2_u128 | h3_u128;
//     // unsafe { let i = _mm_sha1msg1_epu32(h0h1h2h3_u128, 0);
//     // }
//     // _mm_sha1msg2_epu32()
//     // _mm_sha1nexte_epu32()
//     // _mm_sha1rnds4_epu32()
// }

#[test]
fn assert_hash_values_integrity_for_each_step_00_to_15() {
    let mut hasher = instantiate_and_preprocess_abc_message();
    let words = HasherWords::from(&hasher.padding);
    completed_words(&mut hasher);

    let mut state = hasher.state.clone();

    assert_eq!([state.0 .0, state.0 .1, state.0 .2, state.0 .3, state.0 .4], [H0, H1, H2, H3, H4]);

    Sha160(state.0 .0, &mut state.0 .1, state.0 .2, state.0 .3, &mut state.0 .4, words[0]).rounds_00_19();
    assert_eq!(
        [state.0 .4, state.0 .0, state.0 .1, state.0 .2, state.0 .3],
        [0x0116FC33, 0x67452301, 0x7BF36AE2, 0x98BADCFE, 0x10325476]
    );

    Sha160(state.0 .4, &mut state.0 .0, state.0 .1, state.0 .2, &mut state.0 .3, words[1]).rounds_00_19();
    assert_eq!(
        [state.0 .3, state.0 .4, state.0 .0, state.0 .1, state.0 .2],
        [0x8990536D, 0x0116FC33, 0x59D148C0, 0x7BF36AE2, 0x98BADCFE]
    );

    Sha160(state.0 .3, &mut state.0 .4, state.0 .0, state.0 .1, &mut state.0 .2, words[2]).rounds_00_19();
    assert_eq!(
        [state.0 .2, state.0 .3, state.0 .4, state.0 .0, state.0 .1],
        [0xA1390F08, 0x8990536D, 0xC045BF0C, 0x59D148C0, 0x7BF36AE2]
    );

    Sha160(state.0 .2, &mut state.0 .3, state.0 .4, state.0 .0, &mut state.0 .1, words[3]).rounds_00_19();
    assert_eq!(
        [state.0 .1, state.0 .2, state.0 .3, state.0 .4, state.0 .0],
        [0xCDD8E11B, 0xA1390F08, 0x626414DB, 0xC045BF0C, 0x59D148C0]
    );

    Sha160(state.0 .1, &mut state.0 .2, state.0 .3, state.0 .4, &mut state.0 .0, words[4]).rounds_00_19();
    assert_eq!(
        [state.0 .0, state.0 .1, state.0 .2, state.0 .3, state.0 .4],
        [0xCFD499DE, 0xCDD8E11B, 0x284E43C2, 0x626414DB, 0xC045BF0C]
    );

    Sha160(state.0 .0, &mut state.0 .1, state.0 .2, state.0 .3, &mut state.0 .4, words[5]).rounds_00_19();
    assert_eq!(
        [state.0 .4, state.0 .0, state.0 .1, state.0 .2, state.0 .3],
        [0x3FC7CA40, 0xCFD499DE, 0xF3763846, 0x284E43C2, 0x626414DB]
    );

    Sha160(state.0 .4, &mut state.0 .0, state.0 .1, state.0 .2, &mut state.0 .3, words[6]).rounds_00_19();
    assert_eq!(
        [state.0 .3, state.0 .4, state.0 .0, state.0 .1, state.0 .2],
        [0x993E30C1, 0x3FC7CA40, 0xB3F52677, 0xF3763846, 0x284E43C2]
    );

    Sha160(state.0 .3, &mut state.0 .4, state.0 .0, state.0 .1, &mut state.0 .2, words[7]).rounds_00_19();
    assert_eq!(
        [state.0 .2, state.0 .3, state.0 .4, state.0 .0, state.0 .1],
        [0x9E8C07D4, 0x993E30C1, 0x0FF1F290, 0xB3F52677, 0xF3763846]
    );

    Sha160(state.0 .2, &mut state.0 .3, state.0 .4, state.0 .0, &mut state.0 .1, words[8]).rounds_00_19();
    assert_eq!(
        [state.0 .1, state.0 .2, state.0 .3, state.0 .4, state.0 .0],
        [0x4B6AE328, 0x9E8C07D4, 0x664F8C30, 0x0FF1F290, 0xB3F52677]
    );

    Sha160(state.0 .1, &mut state.0 .2, state.0 .3, state.0 .4, &mut state.0 .0, words[9]).rounds_00_19();
    assert_eq!(
        [state.0 .0, state.0 .1, state.0 .2, state.0 .3, state.0 .4],
        [0x8351F929, 0x4B6AE328, 0x27A301F5, 0x664F8C30, 0xFF1F290]
    );

    Sha160(state.0 .0, &mut state.0 .1, state.0 .2, state.0 .3, &mut state.0 .4, words[10]).rounds_00_19();
    assert_eq!(
        [state.0 .4, state.0 .0, state.0 .1, state.0 .2, state.0 .3],
        [0xFBDA9E89, 0x8351F929, 0x12DAB8CA, 0x27A301F5, 0x664F8C30]
    );

    Sha160(state.0 .4, &mut state.0 .0, state.0 .1, state.0 .2, &mut state.0 .3, words[11]).rounds_00_19();
    assert_eq!(
        [state.0 .3, state.0 .4, state.0 .0, state.0 .1, state.0 .2],
        [0x63188FE4, 0xFBDA9E89, 0x60D47E4A, 0x12DAB8CA, 0x27A301F5]
    );

    Sha160(state.0 .3, &mut state.0 .4, state.0 .0, state.0 .1, &mut state.0 .2, words[12]).rounds_00_19();
    assert_eq!(
        [state.0 .2, state.0 .3, state.0 .4, state.0 .0, state.0 .1],
        [0x4607B664, 0x63188FE4, 0x7EF6A7A2, 0x60D47E4A, 0x12DAB8CA]
    );

    Sha160(state.0 .2, &mut state.0 .3, state.0 .4, state.0 .0, &mut state.0 .1, words[13]).rounds_00_19();
    assert_eq!(
        [state.0 .1, state.0 .2, state.0 .3, state.0 .4, state.0 .0],
        [0x9128F695, 0x4607B664, 0x18C623F9, 0x7EF6A7A2, 0x60D47E4A]
    );

    Sha160(state.0 .1, &mut state.0 .2, state.0 .3, state.0 .4, &mut state.0 .0, words[14]).rounds_00_19();
    assert_eq!(
        [state.0 .0, state.0 .1, state.0 .2, state.0 .3, state.0 .4],
        [0x196BEE77, 0x9128F695, 0x1181ED99, 0x18C623F9, 0x7EF6A7A2]
    );

    Sha160(state.0 .0, &mut state.0 .1, state.0 .2, state.0 .3, &mut state.0 .4, words[15]).rounds_00_19();
    assert_eq!(
        [state.0 .4, state.0 .0, state.0 .1, state.0 .2, state.0 .3],
        [0x20BDD62F, 0x196BEE77, 0x644A3DA5, 0x1181ED99, 0x18C623F9]
    );
}

#[test]
fn assert_hash_values_integrity_for_each_step_16_to_19() {
    let mut hasher = instantiate_and_preprocess_abc_message();
    let mut words = HasherWords::from(&hasher.padding);
    completed_words(&mut hasher);

    let mut state = hasher.state.clone();
    state.block_00_15(&mut words);

    Sha160BitsState::next_words(&mut words);

    Sha160(state.0 .4, &mut state.0 .0, state.0 .1, state.0 .2, &mut state.0 .3, words[0]).rounds_00_19();
    assert_eq!(
        [state.0 .3, state.0 .4, state.0 .0, state.0 .1, state.0 .2],
        [0x4E925823, 0x20BDD62F, 0xC65AFB9D, 0x644A3DA5, 0x1181ED99]
    );

    Sha160(state.0 .3, &mut state.0 .4, state.0 .0, state.0 .1, &mut state.0 .2, words[1]).rounds_00_19();
    assert_eq!(
        [state.0 .2, state.0 .3, state.0 .4, state.0 .0, state.0 .1],
        [0x82AA6728, 0x4E925823, 0xC82F758B, 0xC65AFB9D, 0x644A3DA5]
    );

    Sha160(state.0 .2, &mut state.0 .3, state.0 .4, state.0 .0, &mut state.0 .1, words[2]).rounds_00_19();
    assert_eq!(
        [state.0 .1, state.0 .2, state.0 .3, state.0 .4, state.0 .0],
        [0xDC64901D, 0x82AA6728, 0xD3A49608, 0xC82F758B, 0xC65AFB9D]
    );

    Sha160(state.0 .1, &mut state.0 .2, state.0 .3, state.0 .4, &mut state.0 .0, words[3]).rounds_00_19();
    assert_eq!(
        [state.0 .0, state.0 .1, state.0 .2, state.0 .3, state.0 .4],
        [0xFD9E1D7D, 0xDC64901D, 0x20AA99CA, 0xD3A49608, 0xC82F758B]
    );

    Sha160(state.0 .0, &mut state.0 .1, state.0 .2, state.0 .3, &mut state.0 .4, words[4]).rounds_20_39();
    assert_eq!(
        [state.0 .4, state.0 .0, state.0 .1, state.0 .2, state.0 .3],
        [0x1A37B0CA, 0xFD9E1D7D, 0x77192407, 0x20AA99CA, 0xD3A49608]
    );

    Sha160(state.0 .4, &mut state.0 .0, state.0 .1, state.0 .2, &mut state.0 .3, words[5]).rounds_20_39();
    assert_eq!(
        [state.0 .3, state.0 .4, state.0 .0, state.0 .1, state.0 .2],
        [0x33A23BFC, 0x1A37B0CA, 0x7F67875F, 0x77192407, 0x20AA99CA]
    );

    Sha160(state.0 .3, &mut state.0 .4, state.0 .0, state.0 .1, &mut state.0 .2, words[6]).rounds_20_39();
    assert_eq!(
        [state.0 .2, state.0 .3, state.0 .4, state.0 .0, state.0 .1],
        [0x21283486, 0x33A23BFC, 0x868DEC32, 0x7F67875F, 0x77192407]
    );

    Sha160(state.0 .2, &mut state.0 .3, state.0 .4, state.0 .0, &mut state.0 .1, words[7]).rounds_20_39();
    assert_eq!(
        [state.0 .1, state.0 .2, state.0 .3, state.0 .4, state.0 .0],
        [0xD541F12D, 0x21283486, 0x0CE88EFF, 0x868DEC32, 0x7F67875F]
    );

    Sha160(state.0 .1, &mut state.0 .2, state.0 .3, state.0 .4, &mut state.0 .0, words[8]).rounds_20_39();
    assert_eq!(
        [state.0 .0, state.0 .1, state.0 .2, state.0 .3, state.0 .4],
        [0xC7567DC6, 0xD541F12D, 0x884A0D21, 0x0CE88EFF, 0x868DEC32]
    );

    Sha160(state.0 .0, &mut state.0 .1, state.0 .2, state.0 .3, &mut state.0 .4, words[9]).rounds_20_39();
    assert_eq!(
        [state.0 .4, state.0 .0, state.0 .1, state.0 .2, state.0 .3],
        [0x48413BA4, 0xC7567DC6, 0x75507C4B, 0x884A0D21, 0x0CE88EFF]
    );

    Sha160(state.0 .4, &mut state.0 .0, state.0 .1, state.0 .2, &mut state.0 .3, words[10]).rounds_20_39();
    assert_eq!(
        [state.0 .3, state.0 .4, state.0 .0, state.0 .1, state.0 .2],
        [0xBE35FBD5, 0x48413BA4, 0xB1D59F71, 0x75507C4B, 0x884A0D21]
    );

    Sha160(state.0 .3, &mut state.0 .4, state.0 .0, state.0 .1, &mut state.0 .2, words[11]).rounds_20_39();
}
