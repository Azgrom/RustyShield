use lib::Sha1Context;
use std::{env, fs, process};

fn main() {
    let args: Vec<String> = env::args().collect();

    let file_path = parse_arguments(args.iter()).unwrap_or_else(|err| {
        eprintln!("{}", err);
        process::exit(1);
    });

    let mut sha1context = Sha1Context::default();
    fs::read(file_path)
        .unwrap_or_else(|_| panic!("Not able to read {}", file_path))
        .chunks(128)
        .for_each(|line| sha1context.write(line.as_ref()));

    sha1context.finish();

    println!("SHA1({}) = {}", file_path, sha1context.hex_hash())
}

fn parse_arguments<'a>(
    mut args: impl Iterator<Item = &'a String>,
) -> Result<&'a String, &'static str> {
    match args.next() {
        Some(_) => (),
        None => return Err("Executable cannot have no name"),
    };

    let file_path = match args.next() {
        Some(file_path) => file_path,
        None => return Err("Did not receive a file path"),
    };

    Ok(file_path)
}
