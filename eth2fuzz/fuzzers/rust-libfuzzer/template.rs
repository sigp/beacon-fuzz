#![no_main]
extern crate libfuzzer_sys;
use libfuzzer_sys::fuzz_target;

extern crate fuzz_targets;
use fuzz_targets::fuzz_###TARGET### as fuzz_target;


extern crate lazy_static;
use lazy_static::lazy_static;

extern crate walkdir;
use walkdir::WalkDir;

extern crate types;
extern crate ssz;
extern crate ssz_derive;

use ssz::Decode; // Encode
use types::{BeaconState, MainnetEthSpec};

use std::fs::{File};
use std::io;
use std::io::Read;
use std::process;
use std::fs::OpenOptions;
use std::io::prelude::*;

extern crate rand;
use rand::thread_rng;
use rand::seq::SliceRandom;

/// List file in folder and return list of files paths
#[inline(always)]
fn list_files_in_folder(path_str: &String) -> 
	Result<Vec<String>, ()> {
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
fn read_contents_from_path(path_str: &String) -> 
	Result<Vec<u8>, io::Error> {
	    let mut buffer: Vec<u8> = Vec::new();
	    let file_path = std::path::PathBuf::from(path_str);

	    let mut file = File::open(file_path)?;
	    file.read_to_end(&mut buffer)?;
	    // We force to close the file
	    drop(file);
	    Ok(buffer)
}

/// Load a beaconstate ssz file from the path provided 
/// and return a BeaconState
#[inline(always)]
fn get_beaconstate(path_str: &String) -> 
	Result<BeaconState<MainnetEthSpec>, ssz::DecodeError> {
    	let beacon_blob = read_contents_from_path(&path_str).unwrap();
    	let beacon_blob = BeaconState::from_ssz_bytes(&beacon_blob)?;
    	Ok(beacon_blob)
}

#[inline(always)]
fn fuzz_logging(path: &String) {
    // get the pid of the thread
    let pid = process::id();
    // open the logging file - usefull to find beaconstate file when one thread crash
    // PID of the crash thread is inside fuzzer-honggfuzz/hfuzz_workspace/TARGET/HONGGFUZZ.REPORT.TXT
    let mut file = OpenOptions::new()
    	.append(true)
    	.create(true)
    	.open("all_fuzz_log_fuzz.txt").unwrap();

    // write info in the logging file
    if let Err(e) = writeln!(file, "pid: {} | beaconstate: {}", pid, path) {
        eprintln!("Couldn't write to file: {}", e);
    }
}

lazy_static! {

	static ref BEACONSTATE: BeaconState<MainnetEthSpec> = {

		// provide only valid beaconstate in this folder
		// valid ssz beaconstate here: ../../../corpora/mainnet/beaconstate/
	    use std::env;
	    let key = "ETH2FUZZ_BEACONSTATE";
	    let mut beacon_path: String = "".to_string();
	    match env::var(key) {
	        Ok(val) => beacon_path = val,
	        Err(e) => println!("couldn't interpret {}: {}", key, e),
	    };
	    let mut list_path = match list_files_in_folder(&beacon_path){
	        Ok(list_path) => list_path,
	        Err(e) => panic!(
	            "list_files_in_folder failed: {:?}",
	            e
	        ),
	    };

	    // shuffle the list of beaconstate files
	    let mut rng = thread_rng();
	    list_path.shuffle(&mut rng);

	    // create empty path string
	    let mut path: String = String::new();
	    // create fake result with and Error
	    let mut beaconstate: 
	        Result<BeaconState<MainnetEthSpec>, ssz::DecodeError> = 
	            Err(ssz::DecodeError::BytesInvalid(
	                "fake_error".to_string()));

	    // iterate over all the list until we found one beaconstate
	    // that is valid
	    for beacon in list_path {
	        beaconstate = get_beaconstate(&beacon);
	        // One valid beaconstate found
	        if beaconstate.is_ok() {
	            path = beacon;
	            break;
	        }
	    }

	    // verify that we found one valid beaconstate, otherwise crash
	    if path.is_empty() || beaconstate.is_err() {
	        panic!("No valid beaconstate in the seed folder");
	    }

	    // log pid and beaconstate file path to the fuzzer's logs
	    fuzz_logging(&path);

	    beaconstate.unwrap().clone()
	};
}

fuzz_target!(|data: &[u8]| {
    fuzz_target(BEACONSTATE.clone(), data);
});
