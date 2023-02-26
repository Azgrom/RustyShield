use n_bit_words_lib::U32Word;

#[test]
fn lower_hex_format() {
    let u32_word_min = U32Word::from(u32::MIN);
    let u32_word_max = U32Word::from(u32::MAX);
    let u32_word_mid = U32Word::from((u32::MAX / (u16::MAX as u32)) - 2);

    assert_eq!(format!("0x{:08x}", u32_word_min), "0x00000000");
    assert_eq!(format!("0x{:08x}", u32_word_mid), "0x0000ffff");
    assert_eq!(format!("0x{:x}", u32_word_max), "0xffffffff");
}

#[test]
fn upper_hex_format() {
    let u32_word_min = U32Word::from(u32::MIN);
    let u32_word_max = U32Word::from(u32::MAX);
    let u32_word_mid = U32Word::from((u32::MAX / (u16::MAX as u32)) - 2);

    assert_eq!(format!("0x{:08X}", u32_word_min), "0x00000000");
    assert_eq!(format!("0x{:08X}", u32_word_mid), "0x0000FFFF");
    assert_eq!(format!("0x{:X}", u32_word_max), "0xFFFFFFFF");
}
