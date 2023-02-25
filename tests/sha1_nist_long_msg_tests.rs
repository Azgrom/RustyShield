use std::{
    env,
    fs,
    path::Path,
    process,
    hash::{BuildHasher, Hasher}
};
use hash_ctx_lib::HasherContext;
use rs_sha1_lib::Sha1State;

struct Sha1LongMsg {
    message: Vec<u8>,
    message_digest: String,
}

impl Sha1LongMsg {
    fn load() -> Vec<Self> {
        let cargo_manifest_dir =
            env::var("CARGO_MANIFEST_DIR").expect("Unable to access CARGO_MANIFEST_DIR");
        let project_path = Path::new(&cargo_manifest_dir);
        let path = Path::new("shabytetestvectors/SHA1LongMsg.rsp");
        let file_path = project_path.join(Path::new("tests/").join(path));

        let long_msgs: Vec<String> = fs::read_to_string(file_path)
            .unwrap_or_else(|err| {
                eprintln!(
                    "Error trying to open and read SHA1LongMsg.rsp, received {}",
                    err
                );
                process::exit(1);
            })
            .lines()
            .map(|s| s.to_string())
            .collect();

        let mut sha1_long_msgs: Vec<Self> = Vec::new();
        let mut chunk_offset = 7;
        while long_msgs.len() >= chunk_offset + 4 {
            let (_, hash) = (&long_msgs[chunk_offset..chunk_offset + 4][1]).split_at(6);
            let (_, digest) = (&long_msgs[chunk_offset..chunk_offset + 4][2]).split_at(5);

            sha1_long_msgs.push(Self {
                message: hash
                    .chars()
                    .map(|c| u8::from_str_radix(&c.to_string(), 16).unwrap())
                    .collect::<Vec<u8>>()
                    .chunks(2)
                    .into_iter()
                    .map(|t| t[0] << 4 | t[1])
                    .collect::<Vec<u8>>(),
                message_digest: digest.to_string(),
            });

            chunk_offset += 4;
        }

        sha1_long_msgs
    }
}


#[test]
fn compare_long_messages_provided_by_sha_validation_system() {
    let cavs_tests = Sha1LongMsg::load();
    let sha1state = Sha1State::default();

    for long_msg in cavs_tests.iter() {
        let mut hasher = sha1state.build_hasher();

        hasher.write(long_msg.message.as_ref());

        assert_eq!(hasher.to_lower_hex(), long_msg.message_digest);
    }
}
