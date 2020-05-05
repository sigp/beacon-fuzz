#[macro_use] extern crate afl;
extern crate fuzz_targets;
use fuzz_targets::fuzz_###TARGET### as fuzz_target;

extern crate walkdir;
extern crate types;

extern crate ssz;
extern crate ssz_derive;

use ssz::Decode; // Encode

use types::{BeaconState, MainnetEthSpec};

use std::fs::{File};
use std::io;
use std::io::Read;

use std::process;
use walkdir::WalkDir;

use std::fs::OpenOptions;
use std::io::prelude::*;

/// List file in folder and return list of files paths
#[inline(always)]
fn list_files_in_folder(path_str: &String) -> Result<Vec<String>, ()> {
    let mut list: Vec<String> = Vec::<String>::new();

    for entry in WalkDir::new(path_str).into_iter().filter_map(|e| e.ok()) {
        if entry.metadata().unwrap().is_file() {
            //println!("{}", entry.path().display());
            list.push(entry.path().display().to_string());
        }
    }
    Ok(list)
}


/// Read the contents from file path
#[inline(always)]
fn read_contents_from_path(path_str: &String) -> Result<Vec<u8>, io::Error> {
    let mut buffer: Vec<u8> = Vec::new();
    let file_path = std::path::PathBuf::from(path_str);

    let mut file = File::open(file_path)?;
    file.read_to_end(&mut buffer)?;
    // We force to close the file
    drop(file);
    Ok(buffer)
}

/// Load a beaconstate ssz file from the path provided and return a BeaconState
#[inline(always)]
fn get_beaconstate(path_str: &String) -> Result<BeaconState<MainnetEthSpec>, ssz::DecodeError> {

    let beacon_blob = read_contents_from_path(&path_str).unwrap();
    let beacon_blob = BeaconState::from_ssz_bytes(&beacon_blob)?;
    Ok(beacon_blob)
}

fn main() {

	// get the pid of the thread
	let pid = process::id();

	// open the logging file - usefull to find which beaconstate file where used when one thread crashed
	let mut file = OpenOptions::new().append(true).create(true).open("all_fuzz_log_afl.txt").unwrap();

	// provide only valid beaconstate in this folder
	// valid ssz beaconstate here: ../../../corpora/mainnet/beaconstate/
    let list_path = match list_files_in_folder(&"../corpora/beaconstate".to_string()){
        Ok(list_path) => list_path,
        Err(e) => panic!(
            "list_files_in_folder failed: {:?}",
            e
        ),
    };

    // search for only valid beaconstate files
    let mut valid_beacon_list: Vec<(String, BeaconState<MainnetEthSpec>)> = Vec::new();

    for beacon in list_path {
        if let Ok(ret) = get_beaconstate(&beacon) {
            valid_beacon_list.push((beacon,ret));
        }
    }

    // verify that some beaconstate are valid, otherwise crash
    if valid_beacon_list.len() == 0 {
        panic!("No valid beaconstate in the seed folder");
    }

    //use the pid to select a valid beaconstate file
    let idx = pid % valid_beacon_list.len() as u32;
    let (path, beaconstate) = &valid_beacon_list[idx as usize];

    // write info in the logging file
    if let Err(e) = writeln!(file, "pid: {} | beaconstate: {}", pid, path) {
        eprintln!("Couldn't write to file: {}", e);
    }

    // Run fuzzing loop
    fuzz!(|data|{
        fuzz_target(data, beaconstate.clone());
    });
}
