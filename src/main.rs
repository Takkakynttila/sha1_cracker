use sha1::Digest;
use std::{
    env,
    error::Error,
    fs::File,
    io::{BufRead, BufReader},
};

const SHA1_HEX_STR_LEN: usize = 40;

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = env::args().collect();

    if args.len() != 3 {
        println!("Usage:\nsha1_cracker <wordlist.txt> <sha1 hash>");
        return Ok(());
    }
    let target_hash = args[2].trim();
    if target_hash.len() != SHA1_HEX_STR_LEN {
        return Err("Sha1 hash string length requirement not met!".into());
    }
    let wordlist = File::open(&args[1])?;
    let file_reader = BufReader::new(&wordlist);

    for line in file_reader.lines() {
        let current_line = line?;
        let passwd = current_line.trim();
        let passwd_hashed = &hex::encode(sha1::Sha1::digest(passwd.as_bytes()));

        if target_hash == passwd_hashed {
            println!("Password found: {}", passwd);
            return Ok(());
        }
    }
    println!("Hashed password not found on wordlist.");
    Ok(())
}
