use crate::constants::HEIKE_MONOGATARI;
use crate::sha1::sha1_constants::{H_0, H_1, H_2, H_3, H_4};

#[cfg(test)]

#[test]
fn new_sha1_struct() {
    use crate::sha1::SHA1;

    let expected_sha1 = SHA1 {
        hashes: [H_0, H_1, H_2, H_3, H_4],
        d_words_shambling: [0; 80],
        size: 0,
    };

    let resultant_sha1 = SHA1::new();

    assert_eq!(expected_sha1, resultant_sha1);
}

#[test]
fn update_sha1_struct() {
    use crate::sha1::{SHA1, ShaProcess, swab32};
    use crate::sha1::sha1_constants::SHA1_PADDING;
    use crate::sha1::sha1_padding::SHA1Padding;
    use std::str::from_utf8;

    let mut x = SHA1::new();
    let mut padding: Vec<u32> = SHA1_PADDING
        .to_vec()
        .iter()
        .map(|x| *x as u32)
        .collect::<Vec<u32>>();
    let pad: [u32; 2] = [
        swab32(&((x.size >> 29) as u32)),
        swab32(&((x.size << 3) as u32)),
    ];

    let i = 1 + (63 & (55 - (x.size & 63)));
    x.update(&mut padding, i);
    x.update(&mut pad.to_vec(), 8);

    let mut h = SHA1Padding::new(String::from(from_utf8(HEIKE_MONOGATARI).ok().unwrap()))
        .convert_padding_to_words().to_vec();
    let h_len = h.len();
    x.update(&mut h, h_len);

    println!("test");
}

// #[test]
// fn finalize_sha1() {
//
// }
