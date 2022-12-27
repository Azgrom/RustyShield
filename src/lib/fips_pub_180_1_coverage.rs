use crate::{
    DWords, Sha1Context, H0, H1, H2, H3, H4, SHA_CBLOCK, SHA_CBLOCK_LAST_INDEX, SHA_OFFSET_PAD,
};

const MESSAGE: &str = "abc";

fn instantiate_and_preprocess_abc_message() -> Sha1Context {
    let mut context = Sha1Context::default();
    Sha1Context::write(&mut context, MESSAGE.as_ref());
    let zero_padding_length = Sha1Context::zero_padding_length(&context);
    let mut offset_pad: [u8; SHA_OFFSET_PAD as usize] = [0u8; SHA_OFFSET_PAD as usize];
    let pad_len: [u8; 8] = (context.size * 8).to_be_bytes();

    offset_pad[0] = 0x80;
    offset_pad[zero_padding_length - 8..zero_padding_length].clone_from_slice(&pad_len);
    let len_w = (context.size & SHA_CBLOCK_LAST_INDEX as u64) as u8;
    context.size += zero_padding_length as u64;
    let left = (SHA_CBLOCK - len_w as u32) as usize;
    DWords::skippable_offset(&mut context.words, &offset_pad[..left], len_w);
    context
}

#[test]
fn start_processing_block_integrity() {
    let mut context = Sha1Context::default();
    Sha1Context::write(&mut context, MESSAGE.as_ref());

    let expected_block_of_words_1 = [
        0x61626300u32,
        0u32,
        0u32,
        0u32,
        0u32,
        0u32,
        0u32,
        0u32,
        0u32,
        0u32,
        0u32,
        0u32,
        0u32,
        0u32,
        0u32,
        0u32,
    ];
    assert_eq!(context.words, expected_block_of_words_1);

    Sha1Context::finish(&mut context);

    let expected_block_of_words_2 = [
        0x61626380u32,
        0u32,
        0u32,
        0u32,
        0u32,
        0u32,
        0u32,
        0u32,
        0u32,
        0u32,
        0u32,
        0u32,
        0u32,
        0u32,
        0u32,
        0x18u32,
    ];
    assert_eq!(context.words, expected_block_of_words_2);
}

#[test]
fn hash_values_integrity_for_each_step_00_to_15() {
    let context = instantiate_and_preprocess_abc_message();

    let [mut a, mut b, mut c, mut d, mut e] = context.hashes.to_slice().clone();

    assert_eq!([a, b, c, d, e], [H0, H1, H2, H3, H4]);
    Sha1Context::block_00_15(a, &mut b, c, d, &mut e, context.words[0]);

    assert_eq!(
        [e, a, b, c, d],
        [0x0116FC33, 0x67452301, 0x7BF36AE2, 0x98BADCFE, 0x10325476]
    );
    Sha1Context::block_00_15(e, &mut a, b, c, &mut d, context.words[1]);

    assert_eq!(
        [d, e, a, b, c],
        [0x8990536D, 0x0116FC33, 0x59D148C0, 0x7BF36AE2, 0x98BADCFE]
    );
    Sha1Context::block_00_15(d, &mut e, a, b, &mut c, context.words[2]);

    assert_eq!(
        [c, d, e, a, b],
        [0xA1390F08, 0x8990536D, 0xC045BF0C, 0x59D148C0, 0x7BF36AE2]
    );
    Sha1Context::block_00_15(c, &mut d, e, a, &mut b, context.words[3]);

    assert_eq!(
        [b, c, d, e, a],
        [0xCDD8E11B, 0xA1390F08, 0x626414DB, 0xC045BF0C, 0x59D148C0]
    );
    Sha1Context::block_00_15(b, &mut c, d, e, &mut a, context.words[4]);

    assert_eq!(
        [a, b, c, d, e],
        [0xCFD499DE, 0xCDD8E11B, 0x284E43C2, 0x626414DB, 0xC045BF0C]
    );
    Sha1Context::block_00_15(a, &mut b, c, d, &mut e, context.words[5]);

    assert_eq!(
        [e, a, b, c, d],
        [0x3FC7CA40, 0xCFD499DE, 0xF3763846, 0x284E43C2, 0x626414DB]
    );
    Sha1Context::block_00_15(e, &mut a, b, c, &mut d, context.words[6]);

    assert_eq!(
        [d, e, a, b, c],
        [0x993E30C1, 0x3FC7CA40, 0xB3F52677, 0xF3763846, 0x284E43C2]
    );
    Sha1Context::block_00_15(d, &mut e, a, b, &mut c, context.words[7]);

    assert_eq!(
        [c, d, e, a, b],
        [0x9E8C07D4, 0x993E30C1, 0x0FF1F290, 0xB3F52677, 0xF3763846]
    );
    Sha1Context::block_00_15(c, &mut d, e, a, &mut b, context.words[8]);

    assert_eq!(
        [b, c, d, e, a],
        [0x4B6AE328, 0x9E8C07D4, 0x664F8C30, 0x0FF1F290, 0xB3F52677]
    );
    Sha1Context::block_00_15(b, &mut c, d, e, &mut a, context.words[9]);

    assert_eq!(
        [a, b, c, d, e],
        [0x8351F929, 0x4B6AE328, 0x27A301F5, 0x664F8C30, 0xFF1F290]
    );
    Sha1Context::block_00_15(a, &mut b, c, d, &mut e, context.words[10]);

    assert_eq!(
        [e, a, b, c, d],
        [0xFBDA9E89, 0x8351F929, 0x12DAB8CA, 0x27A301F5, 0x664F8C30]
    );
    Sha1Context::block_00_15(e, &mut a, b, c, &mut d, context.words[11]);

    assert_eq!(
        [d, e, a, b, c],
        [0x63188FE4, 0xFBDA9E89, 0x60D47E4A, 0x12DAB8CA, 0x27A301F5]
    );
    Sha1Context::block_00_15(d, &mut e, a, b, &mut c, context.words[12]);

    assert_eq!(
        [c, d, e, a, b],
        [0x4607B664, 0x63188FE4, 0x7EF6A7A2, 0x60D47E4A, 0x12DAB8CA]
    );
    Sha1Context::block_00_15(c, &mut d, e, a, &mut b, context.words[13]);

    assert_eq!(
        [b, c, d, e, a],
        [0x9128F695, 0x4607B664, 0x18C623F9, 0x7EF6A7A2, 0x60D47E4A]
    );
    Sha1Context::block_00_15(b, &mut c, d, e, &mut a, context.words[14]);

    assert_eq!(
        [a, b, c, d, e],
        [0x196BEE77, 0x9128F695, 0x1181ED99, 0x18C623F9, 0x7EF6A7A2]
    );
    Sha1Context::block_00_15(a, &mut b, c, d, &mut e, context.words[15]);

    assert_eq!(
        [e, a, b, c, d],
        [0x20BDD62F, 0x196BEE77, 0x644A3DA5, 0x1181ED99, 0x18C623F9]
    );
}
