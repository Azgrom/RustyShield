use lib::constants::{ABC_L, ABC_U};
use lib::sha1_ctx::Sha1Ctx;
use lib::SHAPadding;
use std::borrow::BorrowMut;
use std::ops::Range;
use std::str::from_utf8;

mod lib;

fn main() {
    // let message = Message::new(ABC_L);
    // let message_length = message.len();
    // let message_len_in_bits = message.content_len_in_bits();
    // let message_in_bits = message.content_in_bits();
    // let message_in_bits_len = message_in_bits.len();
    // let z = message.test();

    // println!("{:b}", (128 + 24) as u8);
    // println!("{:b}", (0x80) as u8);

    let mut x: Vec<u8> = vec![1, 2, 3];
    let mut y: Vec<u8> = vec![3, 9, 4];

    let z = x
        .iter()
        .zip(y.iter())
        .fold(0, |acc, (x_i, y_i)| acc | x_i ^ y_i);

    println!("{:08b}", (x[0] ^ y[0]) | (x[1] ^ y[1]) | (x[2] ^ y[2]));

    let z = [[0; 80]; 5];
}

fn dev() {
    println!("abc as bytes = {:?}", ABC_L);
    println!("ABC as bytes = {:?}", ABC_U);

    println!("abc as hex:");
    for byte in ABC_L {
        println!("{:x}", byte);
    }

    let mut string = String::new();
    for byte in ABC_L {
        string.push_str(&*format!("0{:b}", byte));
    }

    println!("string = {}", string);
    let message_length: u64 = string.len() as u64;
    println!("string len = {}", message_length);

    string.push('1');
    println!("string = {}", string);
    println!("string len = {}", string.len());

    let message_length_in_bits = format!("{:b}", message_length).len();

    for _ in string.len()..448 {
        string.push('0');
    }

    println!(
        "message length binary length: {}",
        format!("{:64b}", message_length).len()
    );
    string.push_str(&*format!("{:64b}", message_length));
    println!("string len = {}", string.len());
}
