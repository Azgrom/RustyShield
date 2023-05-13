extern crate alloc;
use crate::sha1state::{H0, H1, H2, H3, H4};
use crate::Sha1State;
use alloc::vec;
use core::hash::Hasher;
use hash_ctx_lib::GenericHasher;
use internal_hasher::{BigEndianBytes, BytePad};
use internal_state::{DWords, GenericStateHasher, Sha160BitsState, Sha160Rotor as Rnd};

const MESSAGE: &str = "abc";

fn instantiate_and_preprocess_abc_message() -> GenericHasher<Sha1State> {
    let mut sha1hasher = GenericHasher::<Sha1State>::default();
    Hasher::write(&mut sha1hasher, MESSAGE.as_ref());
    let pad_len: [u8; 8] = sha1hasher.padding.size.to_be_bytes();
    let zero_padding_length = 64 - ((sha1hasher.padding.size + pad_len.len()) % 64);
    let mut offset_pad = [0u8; 64];
    offset_pad[0] = 0x80;

    Hasher::write(&mut sha1hasher, &offset_pad[..zero_padding_length]);
    sha1hasher.padding[56..].clone_from_slice(&pad_len);

    sha1hasher
}

fn completed_words(hasher: &mut GenericHasher<Sha1State>) {
    let pad_len: [u8; 8] = ((MESSAGE.len() as u64) * 8).to_be_bytes();
    let zero_padding_len = 64 - ((hasher.padding.size + pad_len.len()) % 64);
    let mut offset_pad = [0u8; 64];
    offset_pad[0] = 0x80;

    let mut len_w = hasher.padding.size & hasher.padding.last_index();
    let mut left = 64 - len_w;
    hasher.padding[len_w..len_w + left].clone_from_slice(&offset_pad[..left]);
    hasher.padding.size += zero_padding_len;

    len_w = hasher.padding.size % 64;
    left = 64 - len_w;
    hasher.padding[len_w..len_w + left].clone_from_slice(&pad_len);
    hasher.padding.size += zero_padding_len;
}

#[test]
fn start_processing_rounds_integrity() {
    let mut hasher = GenericHasher::<Sha1State>::default();
    Hasher::write(&mut hasher, MESSAGE.as_ref());

    let expected_rounds_of_words_1: [u8; 64] =
        [vec![0x61, 0x62, 0x63, 0x00], vec![0u8; 60]].concat().try_into().unwrap();
    assert_eq!(hasher.padding, expected_rounds_of_words_1);

    completed_words(&mut hasher);

    let expected_rounds_of_words_2: [u8; 64] =
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
    let words = DWords::<u32>::from(<&[u8; 64]>::try_from(hasher.padding.as_ref()).unwrap());
    completed_words(&mut hasher);

    let mut state = hasher.state.clone();

    assert_eq!([state.0, state.1, state.2, state.3, state.4], [H0, H1, H2, H3, H4]);

    Rnd(&state.0, &mut state.1, &state.2, &state.3, &mut state.4, &words[0]).rounds_00_19();
    assert_eq!(
        [state.4, state.0, state.1, state.2, state.3],
        [0x0116FC33, 0x67452301, 0x7BF36AE2, 0x98BADCFE, 0x10325476]
    );

    Rnd(&state.4, &mut state.0, &state.1, &state.2, &mut state.3, &words[1]).rounds_00_19();
    assert_eq!(
        [state.3, state.4, state.0, state.1, state.2],
        [0x8990536D, 0x0116FC33, 0x59D148C0, 0x7BF36AE2, 0x98BADCFE]
    );

    Rnd(&state.3, &mut state.4, &state.0, &state.1, &mut state.2, &words[2]).rounds_00_19();
    assert_eq!(
        [state.2, state.3, state.4, state.0, state.1],
        [0xA1390F08, 0x8990536D, 0xC045BF0C, 0x59D148C0, 0x7BF36AE2]
    );

    Rnd(&state.2, &mut state.3, &state.4, &state.0, &mut state.1, &words[3]).rounds_00_19();
    assert_eq!(
        [state.1, state.2, state.3, state.4, state.0],
        [0xCDD8E11B, 0xA1390F08, 0x626414DB, 0xC045BF0C, 0x59D148C0]
    );

    Rnd(&state.1, &mut state.2, &state.3, &state.4, &mut state.0, &words[4]).rounds_00_19();
    assert_eq!(
        [state.0, state.1, state.2, state.3, state.4],
        [0xCFD499DE, 0xCDD8E11B, 0x284E43C2, 0x626414DB, 0xC045BF0C]
    );

    Rnd(&state.0, &mut state.1, &state.2, &state.3, &mut state.4, &words[5]).rounds_00_19();
    assert_eq!(
        [state.4, state.0, state.1, state.2, state.3],
        [0x3FC7CA40, 0xCFD499DE, 0xF3763846, 0x284E43C2, 0x626414DB]
    );

    Rnd(&state.4, &mut state.0, &state.1, &state.2, &mut state.3, &words[6]).rounds_00_19();
    assert_eq!(
        [state.3, state.4, state.0, state.1, state.2],
        [0x993E30C1, 0x3FC7CA40, 0xB3F52677, 0xF3763846, 0x284E43C2]
    );

    Rnd(&state.3, &mut state.4, &state.0, &state.1, &mut state.2, &words[7]).rounds_00_19();
    assert_eq!(
        [state.2, state.3, state.4, state.0, state.1],
        [0x9E8C07D4, 0x993E30C1, 0x0FF1F290, 0xB3F52677, 0xF3763846]
    );

    Rnd(&state.2, &mut state.3, &state.4, &state.0, &mut state.1, &words[8]).rounds_00_19();
    assert_eq!(
        [state.1, state.2, state.3, state.4, state.0],
        [0x4B6AE328, 0x9E8C07D4, 0x664F8C30, 0x0FF1F290, 0xB3F52677]
    );

    Rnd(&state.1, &mut state.2, &state.3, &state.4, &mut state.0, &words[9]).rounds_00_19();
    assert_eq!(
        [state.0, state.1, state.2, state.3, state.4],
        [0x8351F929, 0x4B6AE328, 0x27A301F5, 0x664F8C30, 0xFF1F290]
    );

    Rnd(&state.0, &mut state.1, &state.2, &state.3, &mut state.4, &words[10]).rounds_00_19();
    assert_eq!(
        [state.4, state.0, state.1, state.2, state.3],
        [0xFBDA9E89, 0x8351F929, 0x12DAB8CA, 0x27A301F5, 0x664F8C30]
    );

    Rnd(&state.4, &mut state.0, &state.1, &state.2, &mut state.3, &words[11]).rounds_00_19();
    assert_eq!(
        [state.3, state.4, state.0, state.1, state.2],
        [0x63188FE4, 0xFBDA9E89, 0x60D47E4A, 0x12DAB8CA, 0x27A301F5]
    );

    Rnd(&state.3, &mut state.4, &state.0, &state.1, &mut state.2, &words[12]).rounds_00_19();
    assert_eq!(
        [state.2, state.3, state.4, state.0, state.1],
        [0x4607B664, 0x63188FE4, 0x7EF6A7A2, 0x60D47E4A, 0x12DAB8CA]
    );

    Rnd(&state.2, &mut state.3, &state.4, &state.0, &mut state.1, &words[13]).rounds_00_19();
    assert_eq!(
        [state.1, state.2, state.3, state.4, state.0],
        [0x9128F695, 0x4607B664, 0x18C623F9, 0x7EF6A7A2, 0x60D47E4A]
    );

    Rnd(&state.1, &mut state.2, &state.3, &state.4, &mut state.0, &words[14]).rounds_00_19();
    assert_eq!(
        [state.0, state.1, state.2, state.3, state.4],
        [0x196BEE77, 0x9128F695, 0x1181ED99, 0x18C623F9, 0x7EF6A7A2]
    );

    Rnd(&state.0, &mut state.1, &state.2, &state.3, &mut state.4, &words[15]).rounds_00_19();
    assert_eq!(
        [state.4, state.0, state.1, state.2, state.3],
        [0x20BDD62F, 0x196BEE77, 0x644A3DA5, 0x1181ED99, 0x18C623F9]
    );
}

#[test]
fn assert_hash_values_integrity_for_each_step_16_to_19() {
    let mut hasher = instantiate_and_preprocess_abc_message();
    let mut words = DWords::<u32>::from(<&[u8; 64]>::try_from(hasher.padding.as_ref()).unwrap());
    completed_words(&mut hasher);

    let mut state = hasher.state.clone();

    let mut sha160bits_state = Sha160BitsState {
        0: state.0,
        1: state.1,
        2: state.2,
        3: state.3,
        4: state.4,
        5: words,
    };
    sha160bits_state.block_00_15();
    sha160bits_state.next_words();

    state =
        Sha1State(sha160bits_state.0, sha160bits_state.1, sha160bits_state.2, sha160bits_state.3, sha160bits_state.4);
    words = sha160bits_state.5;

    Rnd(&state.4, &mut state.0, &state.1, &state.2, &mut state.3, &words[0]).rounds_00_19();
    assert_eq!(
        [state.3, state.4, state.0, state.1, state.2],
        [0x4E925823, 0x20BDD62F, 0xC65AFB9D, 0x644A3DA5, 0x1181ED99]
    );

    Rnd(&state.3, &mut state.4, &state.0, &state.1, &mut state.2, &words[1]).rounds_00_19();
    assert_eq!(
        [state.2, state.3, state.4, state.0, state.1],
        [0x82AA6728, 0x4E925823, 0xC82F758B, 0xC65AFB9D, 0x644A3DA5]
    );

    Rnd(&state.2, &mut state.3, &state.4, &state.0, &mut state.1, &words[2]).rounds_00_19();
    assert_eq!(
        [state.1, state.2, state.3, state.4, state.0],
        [0xDC64901D, 0x82AA6728, 0xD3A49608, 0xC82F758B, 0xC65AFB9D]
    );

    Rnd(&state.1, &mut state.2, &state.3, &state.4, &mut state.0, &words[3]).rounds_00_19();
    assert_eq!(
        [state.0, state.1, state.2, state.3, state.4],
        [0xFD9E1D7D, 0xDC64901D, 0x20AA99CA, 0xD3A49608, 0xC82F758B]
    );

    Rnd(&state.0, &mut state.1, &state.2, &state.3, &mut state.4, &words[4]).rounds_20_39();
    assert_eq!(
        [state.4, state.0, state.1, state.2, state.3],
        [0x1A37B0CA, 0xFD9E1D7D, 0x77192407, 0x20AA99CA, 0xD3A49608]
    );

    Rnd(&state.4, &mut state.0, &state.1, &state.2, &mut state.3, &words[5]).rounds_20_39();
    assert_eq!(
        [state.3, state.4, state.0, state.1, state.2],
        [0x33A23BFC, 0x1A37B0CA, 0x7F67875F, 0x77192407, 0x20AA99CA]
    );

    Rnd(&state.3, &mut state.4, &state.0, &state.1, &mut state.2, &words[6]).rounds_20_39();
    assert_eq!(
        [state.2, state.3, state.4, state.0, state.1],
        [0x21283486, 0x33A23BFC, 0x868DEC32, 0x7F67875F, 0x77192407]
    );

    Rnd(&state.2, &mut state.3, &state.4, &state.0, &mut state.1, &words[7]).rounds_20_39();
    assert_eq!(
        [state.1, state.2, state.3, state.4, state.0],
        [0xD541F12D, 0x21283486, 0x0CE88EFF, 0x868DEC32, 0x7F67875F]
    );

    Rnd(&state.1, &mut state.2, &state.3, &state.4, &mut state.0, &words[8]).rounds_20_39();
    assert_eq!(
        [state.0, state.1, state.2, state.3, state.4],
        [0xC7567DC6, 0xD541F12D, 0x884A0D21, 0x0CE88EFF, 0x868DEC32]
    );

    Rnd(&state.0, &mut state.1, &state.2, &state.3, &mut state.4, &words[9]).rounds_20_39();
    assert_eq!(
        [state.4, state.0, state.1, state.2, state.3],
        [0x48413BA4, 0xC7567DC6, 0x75507C4B, 0x884A0D21, 0x0CE88EFF]
    );

    Rnd(&state.4, &mut state.0, &state.1, &state.2, &mut state.3, &words[10]).rounds_20_39();
    assert_eq!(
        [state.3, state.4, state.0, state.1, state.2],
        [0xBE35FBD5, 0x48413BA4, 0xB1D59F71, 0x75507C4B, 0x884A0D21]
    );

    Rnd(&state.3, &mut state.4, &state.0, &state.1, &mut state.2, &words[11]).rounds_20_39();
}
