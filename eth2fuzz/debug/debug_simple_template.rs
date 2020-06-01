extern crate fuzz_targets;
use fuzz_targets::fuzz_###TARGET### as fuzz_target;

use std::env;
use std::fs::File;
use std::io;
use std::io::Read;

/// Read the contents from file path
fn read_contents_from_path(path_str: &String) -> Result<Vec<u8>, io::Error> {
    let mut buffer: Vec<u8> = Vec::new();
    let file_path = std::path::PathBuf::from(path_str);

    println!("file_to_process: {:?}", file_path);

    let mut file = File::open(file_path)?;
    file.read_to_end(&mut buffer)?;
    drop(file);
    Ok(buffer)
}

fn main() {
    println!("Start debugging of debug_###TARGET###");
    let args: Vec<String> = env::args().collect();

    // verify files are provided
    if args.len() != 2 {
        println!("Usage: ###TARGET### <file> \n");
        return;
    }

    // read beaconstate file
    let data = read_contents_from_path(&args[1]).expect("Cannot read file");

    // call the fuzzing target
    fuzz_target(&data);

    println!("No crash\n");
}
