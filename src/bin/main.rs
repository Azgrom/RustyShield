use rusty_sha::{sha1_dc_final, sha1_dc_init};

fn main() {

    let mut ctx = sha1_dc_init();
    let mut hash: [u8; 20] = [0; 20];
    sha1_dc_final(&mut hash, ctx);

    let x: Vec<u8> = vec![1, 2, 3];
    let y: Vec<u8> = vec![3, 9, 4];

    let _z = x
        .iter()
        .zip(y.iter())
        .fold(0, |acc, (x_i, y_i)| acc | x_i ^ y_i);

    println!("{:08b}", (x[0] ^ y[0]) | (x[1] ^ y[1]) | (x[2] ^ y[2]));

}
