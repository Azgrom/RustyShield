fn main() {

    let x: Vec<u8> = vec![1, 2, 3];
    let y: Vec<u8> = vec![3, 9, 4];

    let _z = x
        .iter()
        .zip(y.iter())
        .fold(0, |acc, (x_i, y_i)| acc | x_i ^ y_i);

    println!("{:08b}", (x[0] ^ y[0]) | (x[1] ^ y[1]) | (x[2] ^ y[2]));

}
