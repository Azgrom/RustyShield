use std::{env, fs, path::Path, process};

pub struct CAVSLongMsg {
    pub message: Vec<u8>,
    pub expected_message_digest: String,
}

impl CAVSLongMsg {
    pub fn load(path: &str) -> Vec<Self> {
        let cargo_manifest_dir = env::var("CARGO_MANIFEST_DIR").expect("Unable to access CARGO_MANIFEST_DIR");
        let project_path = Path::new(&cargo_manifest_dir);
        let path = Path::new(path);
        let file_path = project_path.join(Path::new("tests/").join(path));

        let long_msgs: Vec<String> = fs::read_to_string(file_path)
            .unwrap_or_else(|err| {
                eprintln!("Error trying to open and read SHA1LongMsg.rsp, received {}", err);
                process::exit(1);
            })
            .lines()
            .map(|s| s.to_string())
            .collect();

        let mut sha256_long_msgs: Vec<Self> = Vec::new();
        let mut chunk_offset = 7;
        while long_msgs.len() >= chunk_offset + 4 {
            let (_, hash) = long_msgs[chunk_offset..chunk_offset + 4][1].split_at(6);
            let (_, digest) = long_msgs[chunk_offset..chunk_offset + 4][2].split_at(5);

            sha256_long_msgs.push(Self {
                message: hash
                    .chars()
                    .map(|c| u8::from_str_radix(&c.to_string(), 16).unwrap())
                    .collect::<Vec<u8>>()
                    .chunks(2)
                    .map(|t| t[0] << 4 | t[1])
                    .collect::<Vec<u8>>(),
                expected_message_digest: digest.to_string(),
            });

            chunk_offset += 4;
        }

        sha256_long_msgs
    }
}
