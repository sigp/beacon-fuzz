extern crate fuzz_targets;
use fuzz_targets::fuzz_###TARGET### as fuzz_target;

use std::env;
use std::fs::File;
use std::io;
use std::io::Read;


extern crate ssz;
use ssz::Decode; // Encode
use types::{BeaconState, MainnetEthSpec};

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
    // for debug_beaconstate, provide the beaconstate file twice
    if args.len() != 3 {
        println!("Usage: ###TARGET### <beaconstate.ssz> <container.ssz>\n");
        return;
    }

    // read beaconstate file
    let beacon_blob = read_contents_from_path(&args[1]).expect("Cannot read beaconstate file");
    // convert bytes to BeaconState structure
    let beaconstate: BeaconState<MainnetEthSpec> =
        BeaconState::from_ssz_bytes(&beacon_blob).expect("Not a valid beaconstate");

    // read container file
    let data = read_contents_from_path(&args[2]).expect("Cannot read container file");

    // call the fuzzing target
    fuzz_target(beaconstate, &data);

    println!("No crash\n");
}
