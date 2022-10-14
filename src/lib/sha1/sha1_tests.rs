use crate::constants::{HEIKE_MONOGATARI, QUICK_FOX};
use crate::sha1::sha1_constants::{H_0, H_1, H_2, H_3, H_4, SHA1_PADDING};
use crate::sha1::sha1_padding::{Padding, SHA1Padding};
use crate::sha1::{swab32, ShaProcess, SHA1};

#[cfg(test)]
#[test]
fn new_sha1_struct() {
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

    let mut h = SHA1Padding::new(HEIKE_MONOGATARI).to_d_words().to_vec();
    let h_len = h.len();
    x.update(&mut h, h_len);

    let hashes: [u32; 5] = [3179583676, 2963362589, 772705852, 3558719495, 860764566];

    assert_eq!(x.unwrap_hashes(), hashes);
}

#[test]
fn finalize_sha1() {
    let mut dwords1 = SHA1Padding::new(HEIKE_MONOGATARI).to_d_words().to_vec();
    let dwords1_len = dwords1.len();
    let hash1 = SHA1::new().update(&mut dwords1, dwords1_len).finalize();
    let expected_hash_1 = [
        10, 179, 229, 95, 211, 211, 209, 95, 236, 5, 106, 173, 76, 17, 122, 198, 142, 157, 113, 97,
    ];
    assert_eq!(hash1, expected_hash_1);
    assert_eq!(hash1, "0ab3e55fd3d3d15fec056aad4c117ac68e9d7161");

    let mut dwords2 = SHA1Padding::new(QUICK_FOX).to_d_words().to_vec();
    let dwords2_len = dwords2.len();
    let hash2 = SHA1::new().update(&mut dwords2, dwords2_len).finalize();
    let expected_hash2 = [
        146, 165, 126, 131, 251, 194, 132, 13, 81, 79, 105, 75, 214, 164, 35, 100, 44, 9, 66, 188,
    ];
    assert_eq!(hash2, expected_hash2);
    assert_eq!(hash2, "92a57e83fbc2840d514f694bd6a423642c0942bc");
    assert_eq!(hash2.to_string(), "[146, 165, 126, 131, 251, 194, 132, 13, 81, 79, 105, 75, 214, 164, 35, 100, 44, 9, 66, 188]")
}
