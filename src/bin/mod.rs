fn main() {
    // Sha1State::default();
}

// use core::hash::{BuildHasher, Hasher};
// use std::{env, fs, process};
//
// use lib::{sha1_state::Sha1State, HashContext};
//
// fn main() {
//     let args: Vec<String> = env::args().collect();
//
//     let file_path = parse_arguments(args.iter()).unwrap_or_else(|err| {
//         eprintln!("{}", err);
//         process::exit(1);
//     });
//
//     let mut hasher = Sha1State::default().build_hasher();
//     fs::read(file_path)
//         .unwrap_or_else(|_| panic!("Not able to read {}", file_path))
//         .chunks(128)
//         .for_each(|line| hasher.write(line.as_ref()));
//
//     println!("SHA1({}) = {}", file_path, hasher.to_hex_string())
// }
//
// fn parse_arguments<'a>(
//     mut args: impl Iterator<Item = &'a String>,
// ) -> Result<&'a String, &'static str> {
//     match args.next() {
//         Some(_) => (),
//         None => return Err("Executable cannot have no name"),
//     };
//
//     let file_path = match args.next() {
//         Some(file_path) => file_path,
//         None => return Err("Did not receive a file path"),
//     };
//
//     Ok(file_path)
// }
