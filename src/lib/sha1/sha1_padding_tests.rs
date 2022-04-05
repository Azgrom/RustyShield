use crate::constants::{ABC_L, ABC_U, HEIKE_MONOGATARI, QUICK_FOX};
use crate::sha1::sha1_padding::*;

#[cfg(test)]

#[test]
fn padding_constructor_with_text() {
    use crate::sha1::sha1_constants::ShaPadding;
    use std::str::from_utf8;

    let resultant_array1: ShaPadding =
        SHA1Padding::new(String::from(from_utf8(ABC_L).ok().unwrap())).unwrap();
    let expected_array1 = [
        97, 98, 99, 128, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 24,
    ];
    assert_eq!(resultant_array1, expected_array1);

    let resultant_array2 = SHA1Padding::new(String::from(from_utf8(ABC_U).ok().unwrap())).unwrap();
    let expected_array2: ShaPadding = [
        65, 66, 67, 128, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 24,
    ];
    assert_eq!(resultant_array2, expected_array2);

    let resultant_array3 =
        SHA1Padding::new(String::from(from_utf8(QUICK_FOX).ok().unwrap())).unwrap();
    let expected_array3: ShaPadding = [
        84, 104, 101, 32, 113, 117, 105, 99, 107, 32, 98, 114, 111, 119, 110, 32, 102, 111, 120,
        32, 106, 117, 109, 112, 115, 32, 111, 118, 101, 114, 32, 116, 104, 101, 32, 108, 97, 122,
        121, 32, 100, 111, 103, 128, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 88,
    ];
    assert_eq!(resultant_array3, expected_array3);

    let resultant_array4 =
        SHA1Padding::new(String::from(from_utf8(HEIKE_MONOGATARI).ok().unwrap())).unwrap();
    let expected_array4 = [
        128, 104, 101, 32, 115, 111, 117, 110, 100, 32, 111, 102, 32, 116, 104, 101, 32, 71, 105,
        111, 110, 32, 83, 104, 197, 141, 106, 97, 32, 98, 101, 108, 108, 115, 32, 101, 99, 104,
        111, 101, 115, 32, 116, 104, 101, 32, 105, 109, 112, 101, 114, 109, 97, 110, 101, 110, 99,
        101, 32, 111, 102, 10, 107, 220,
    ];
    assert_eq!(resultant_array4, expected_array4);
}

#[test]
fn create_dword_from_padding() {
    use std::str::from_utf8;

    let dwords1 = SHA1Padding::new(String::from(from_utf8(QUICK_FOX).ok().unwrap()))
        .convert_padding_to_words();

    let expected_array1 = [
        1416127776, 1903520099, 1797284466, 1870097952, 1718581280, 1786080624, 1931505526,
        1701978228, 1751457900, 1635416352, 1685022592, 0, 0, 0, 0, 344,
    ];
    assert_eq!(dwords1, expected_array1);

    let dwords2 = SHA1Padding::new(String::from(from_utf8(HEIKE_MONOGATARI).ok().unwrap()))
        .convert_padding_to_words();

    let expected_array2 = [
        2154325280, 1936684398, 1679847270, 544499813, 541550959, 1847612264, 3314379361,
        543319404, 1819484261, 1667788645, 1931506792, 1696622957, 1885696621, 1634624878,
        1667571823, 1711959004,
    ];
    assert_eq!(dwords2, expected_array2);
}
