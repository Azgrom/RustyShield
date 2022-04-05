use std::mem;
use std::ops::Range;
// use rusty_sha::{sha1_dc_final, sha1_dc_init};

fn main() {

    let x: [u8; 3] = [1, 2, 3];
    let mut y: [u8; 2] = [0; 2];
    let z = x.iter();

    let mut range = Range {start: 0, end: 2};
    y.clone_from_slice(&x[range.clone()]);

    range.start += 1;
    range.end += 1;
    y.clone_from_slice(&x[range]);

    let i: usize = 5;
    println!("{}", mem::size_of_val(&i));

    println!("Test");
}
