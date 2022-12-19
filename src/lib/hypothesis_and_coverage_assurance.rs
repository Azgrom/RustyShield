use crate::DWords;
use core::ops::{BitOr, Shl, Shr};

#[test]
fn fips180_rotate_right_and_left_are_consistent_with_core_rotate_methods() {
    let x: u32 = 5;
    let y: u32 = 2;

    let std_rotate_left = x.rotate_left(y);
    let cus_rotate_left = rotate_left(x, y);
    let std_rotate_right = x.rotate_right(y);
    let cus_rotate_right = rotate_right(x, y);

    assert_eq!(std_rotate_left, cus_rotate_left);
    assert_eq!(std_rotate_right, cus_rotate_right);
}

#[test]
fn compare_fips180_hex_character_big_endianness() {
    let big_endian_zero = 0x0u8;
    let four_bit_str_be_zero = "0000";

    let big_endian_one = 0x1u8;
    let four_bit_str_be_one = "0001";

    let big_endian_two = 0x2u8;
    let four_bit_str_be_two = "0010";

    let big_endian_three = 0x3u8;
    let four_bit_str_be_three = "0011";

    let big_endian_four = 0x4u8;
    let four_bit_str_be_four = "0100";

    let big_endian_five = 0x5u8;
    let four_bit_str_be_five = "0101";

    let big_endian_six = 0x6u8;
    let four_bit_str_be_six = "0110";

    let big_endian_seven = 0x7u8;
    let four_bit_str_be_seven = "0111";

    let big_endian_eight = 0x8u8;
    let four_bit_str_be_eight = "1000";

    let big_endian_nine = 0x9u8;
    let four_bit_str_be_nine = "1001";

    let big_endian_a = 0xau8;
    let four_bit_str_be_a = "1010";

    let big_endian_b = 0xbu8;
    let four_bit_str_be_b = "1011";

    let big_endian_c = 0xcu8;
    let four_bit_str_be_c = "1100";

    let big_endian_d = 0xdu8;
    let four_bit_str_be_d = "1101";

    let big_endian_e = 0xeu8;
    let four_bit_str_be_e = "1110";

    let big_endian_f = 0xfu8;
    let four_bit_str_be_f = "1111";

    assert_eq!(format!("{:04b}", big_endian_zero), *four_bit_str_be_zero);
    assert_eq!(format!("{:04b}", big_endian_one), *four_bit_str_be_one);
    assert_eq!(format!("{:04b}", big_endian_two), *four_bit_str_be_two);
    assert_eq!(format!("{:04b}", big_endian_three), *four_bit_str_be_three);
    assert_eq!(format!("{:04b}", big_endian_four), *four_bit_str_be_four);
    assert_eq!(format!("{:04b}", big_endian_five), *four_bit_str_be_five);
    assert_eq!(format!("{:04b}", big_endian_six), *four_bit_str_be_six);
    assert_eq!(format!("{:04b}", big_endian_seven), *four_bit_str_be_seven);
    assert_eq!(format!("{:04b}", big_endian_eight), *four_bit_str_be_eight);
    assert_eq!(format!("{:04b}", big_endian_nine), *four_bit_str_be_nine);
    assert_eq!(format!("{:04b}", big_endian_a), *four_bit_str_be_a);
    assert_eq!(format!("{:04b}", big_endian_b), *four_bit_str_be_b);
    assert_eq!(format!("{:04b}", big_endian_c), *four_bit_str_be_c);
    assert_eq!(format!("{:04b}", big_endian_d), *four_bit_str_be_d);
    assert_eq!(format!("{:04b}", big_endian_e), *four_bit_str_be_e);
    assert_eq!(format!("{:04b}", big_endian_f), *four_bit_str_be_f);
}

#[test]
fn assert_value_to_append_one_at_message_end() {
    let one_to_append: u8 = 0x80;
    let u4_half = "1000";
    let u4_zero = "0000";
    let mut u8_one_to_append = u4_half.to_string();
    u8_one_to_append.push_str(u4_zero);

    assert_eq!(format!("{:08b}", one_to_append), u8_one_to_append);
}

#[test]
fn first_w_bit_word_in_fips180_documentation_conversion_test() {
    let w32_hex_str: u32 = 0xa103fe23;
    let four_w32_bit_str = [
        "1010", "0001", "0000", "0011", "1111", "1110", "0010", "0011",
    ];
    let w64_hex_str: u64 = 0xa103fe2332ef301a;
    let four_w64_bit_str = [
        "1010", "0001", "0000", "0011", "1111", "1110", "0010", "0011", "0011", "0010", "1110",
        "1111", "0011", "0000", "0001", "1010",
    ];

    let w32_ones_count = w32_hex_str.count_ones();
    let w32_zeros_count = w32_hex_str.count_zeros();
    let w32_bits_count = w32_ones_count + w32_zeros_count;
    let w32_binary_representation = binary_representation(&w32_hex_str.to_be_bytes());

    let w64_ones_count = w64_hex_str.count_ones();
    let w64_zeros_count = w64_hex_str.count_zeros();
    let w64_bits_count = w64_ones_count + w64_zeros_count;
    let w64_binary_representation = binary_representation(&w64_hex_str.to_be_bytes());

    assert_eq!(w32_ones_count, 15);
    assert_eq!(w32_zeros_count, 17);
    assert_eq!(w32_bits_count, u32::BITS);
    assert_eq!(w32_binary_representation, four_w32_bit_str);

    assert_eq!(w64_ones_count, w32_ones_count * 2);
    assert_eq!(w64_zeros_count, w32_zeros_count * 2);
    assert_eq!(w64_bits_count, u64::BITS);
    assert_eq!(w64_binary_representation, four_w64_bit_str);
}

#[test]
fn convert_big_endian_bytes_to_u32() {
    const FIRST_U8: u8 = 0x12;
    const SECOND_U8: u8 = 0x58;
    const THIRD_U8: u8 = 0xfd;
    const FOURTH_U8: u8 = 0xd7;

    let one_byte_stream_vec: &[u8] = &[FIRST_U8];
    let two_byte_stream_vec: &[u8] = &[FIRST_U8, SECOND_U8];
    let three_byte_stream_vec: &[u8] = &[FIRST_U8, SECOND_U8, THIRD_U8];
    let complete_u32_vec: &[u8] = &[FIRST_U8, SECOND_U8, THIRD_U8, FOURTH_U8];

    let manually_computed_single_u8_to_u32 = be_byte_to_u32(one_byte_stream_vec);
    let manually_computed_single_u8_to_u32_hex_str =
        format!("{:x}", manually_computed_single_u8_to_u32);

    let manually_computed_two_u8_to_u32 = two_be_bytes_to_u32(two_byte_stream_vec);
    let manually_computed_two_u8_to_u32_hex_str =
        format!("{:x}", manually_computed_two_u8_to_u32);

    let manually_computed_three_u8_to_u32 = three_be_bytes_to_u32(three_byte_stream_vec);
    let manually_computed_three_u8_to_u32_hex_str =
        format!("{:x}", manually_computed_three_u8_to_u32);

    let manually_computed_complete_u32 = four_be_bytes_to_u32(complete_u32_vec);
    let manually_computed_complete_u32_hex_str =
        format!("{:x}", manually_computed_complete_u32);

    let zeroes_bytes: &[u8] = &[0; 3];
    let one_byte_u32_binding = [zeroes_bytes, one_byte_stream_vec].concat();
    let two_byte_u32_binding = [&zeroes_bytes[..2], two_byte_stream_vec].concat();
    let three_byte_u32_binding = [&zeroes_bytes[..1], three_byte_stream_vec].concat();

    let std_computed_single_u8_to_u32 =
        u32::from_be_bytes(one_byte_u32_binding.try_into().unwrap());
    let std_computed_single_u8_to_u32_hex_str = format!("{:x}", std_computed_single_u8_to_u32);
    let std_computed_two_u8_to_u32 =
        u32::from_be_bytes(two_byte_u32_binding.try_into().unwrap());
    let std_computed_two_u8_to_u32_hex_str = format!("{:x}", std_computed_two_u8_to_u32);
    let std_computed_three_u8_to_u32 =
        u32::from_be_bytes(three_byte_u32_binding.try_into().unwrap());
    let std_computed_three_u8_to_u32_hex_str = format!("{:x}", std_computed_three_u8_to_u32);
    let std_computed_complete_u8_pack_to_u32 =
        u32::from_be_bytes(complete_u32_vec.try_into().unwrap());
    let std_computed_complete_u8_to_u32_hex_str =
        format!("{:x}", std_computed_complete_u8_pack_to_u32);

    assert_eq!(
        std_computed_single_u8_to_u32,
        manually_computed_single_u8_to_u32
    );
    assert_eq!(
        std_computed_single_u8_to_u32_hex_str,
        manually_computed_single_u8_to_u32_hex_str
    );
    assert_eq!(std_computed_two_u8_to_u32, manually_computed_two_u8_to_u32);
    assert_eq!(
        std_computed_two_u8_to_u32_hex_str,
        manually_computed_two_u8_to_u32_hex_str
    );
    assert_eq!(
        std_computed_three_u8_to_u32,
        manually_computed_three_u8_to_u32
    );
    assert_eq!(
        std_computed_three_u8_to_u32_hex_str,
        manually_computed_three_u8_to_u32_hex_str
    );
    assert_eq!(
        std_computed_complete_u8_pack_to_u32,
        manually_computed_complete_u32
    );
    assert_eq!(
        std_computed_complete_u8_to_u32_hex_str,
        manually_computed_complete_u32_hex_str
    );
}

#[test]
fn bit_shift_method_vs_explicit_operation() {
    let unsigned_integer: u32 = 1684234849;

    assert_eq!(unsigned_integer >> 24, unsigned_integer.shr(24));
    assert_eq!(unsigned_integer >> 16, unsigned_integer.shr(16));
    assert_eq!(unsigned_integer >> 8, unsigned_integer.shr(8));
    assert_eq!(unsigned_integer >> 0, unsigned_integer.shr(0));

    assert_eq!(unsigned_integer << 24, unsigned_integer.shl(24));
    assert_eq!(unsigned_integer << 16, unsigned_integer.shl(16));
    assert_eq!(unsigned_integer << 8, unsigned_integer.shl(8));
    assert_eq!(unsigned_integer << 0, unsigned_integer.shl(0));

    let max_u32_unsigned_integer: u32 = u32::MAX;
    assert_eq!(
        max_u32_unsigned_integer.shr(8),
        16_777_215u32,
        "Assert equality for u24::MAX"
    );
    assert_eq!(
        max_u32_unsigned_integer.shr(16),
        65_535u32,
        "Assert equality for u16::MAX"
    );
    assert_eq!(
        max_u32_unsigned_integer.shr(24),
        255_u32,
        "Assert equality for u8::MAX"
    );

    // Assert cast has logic for pointing the least significant bits, by the amount of the new
    // type size. It seems to make use of Copy, because it looses original information in case a
    // cast backwards to original size is immediately made
    assert_eq!(
        max_u32_unsigned_integer as u8,
        (max_u32_unsigned_integer.shl(24) as u32).shr(24) as u8
    );
    assert_eq!(max_u32_unsigned_integer as u8, u8::MAX);
    assert_eq!(max_u32_unsigned_integer.shr(0), u32::MAX);
    assert_eq!((max_u32_unsigned_integer as u8) as u32, u8::MAX as u32);
}

#[test]
fn associative_wrapping_add_property() {
    let u8_max = u8::MAX;
    let half_u8_max = u8::MAX / 2;

    assert_eq!(half_u8_max.wrapping_add(u8_max), half_u8_max - 1);
    assert_eq!(u8_max.wrapping_add(half_u8_max), half_u8_max - 1);

    assert_eq!(
        u8_max.wrapping_add(u8_max).wrapping_add(half_u8_max),
        half_u8_max - 2
    );
    assert_eq!(
        u8_max.wrapping_add(half_u8_max.wrapping_add(u8_max)),
        half_u8_max - 2
    );
    assert_eq!(
        u8_max.wrapping_add(half_u8_max).wrapping_add(u8_max),
        half_u8_max - 2
    );
    assert_eq!(
        u8_max.wrapping_add(u8_max.wrapping_add(half_u8_max)),
        half_u8_max - 2
    );
}

#[test]
fn bytes_padding_into_32bit_words() {
    let first_alphabet_letters: [char; 4] = ['a', 'b', 'c', 'd']; // [0x61, 0x62, 0x63, 0x64]
    let bytes_64_chunk: [u8; 64] = [
        first_alphabet_letters
            .iter()
            .map(|&c| c as u8)
            .collect::<Vec<u8>>(),
        [0; 60].to_vec(),
    ]
    .concat()
    .try_into()
    .unwrap();

    let mut d_words = DWords::default();
    d_words.from(&bytes_64_chunk);

    assert_eq!(
        d_words,
        [0x61626364, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    );
}

fn rotate<R>(x: R, l: R, r: R) -> R
where
    R: Shl<Output = R> + Shr<Output = R> + BitOr<Output = R> + Copy + Sized,
{
    (x << l) | (x >> r)
}

fn rotate_left(x: u32, n: u32) -> u32 {
    rotate(x, n, u32::BITS - n)
}

fn rotate_right(x: u32, n: u32) -> u32 {
    rotate(x, u32::BITS - n, n)
}

fn binary_representation(x: &[u8]) -> Vec<String> {
    let mut result = Vec::with_capacity(x.len() * 2);
    x.iter().for_each(|b| {
        let byte_bits = format!("{:08b}", *b);
        result.push(byte_bits[..4].to_string());
        result.push(byte_bits[4..].to_string());
    });

    result
}

// TODO: Later bench if inlining improves performance
fn be_byte_to_u32(src: &[u8]) -> u32 {
    src[0] as u32
}

// TODO: Later bench if inlining improves performance
fn two_be_bytes_to_u32(src: &[u8]) -> u32 {
    (be_byte_to_u32(src) << 8) | (src[1] as u32)
}

// TODO: Later bench if inlining improves performance
fn three_be_bytes_to_u32(src: &[u8]) -> u32 {
    (two_be_bytes_to_u32(src) << 8) | (src[2] as u32)
}

// TODO: Later bench if inlining improves performance
fn four_be_bytes_to_u32(src: &[u8]) -> u32 {
    (three_be_bytes_to_u32(src) << 8) | (src[3] as u32)
}
