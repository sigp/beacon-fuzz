#[macro_use]
extern crate honggfuzz;

extern crate types;
extern crate walkdir;

extern crate ssz;
extern crate ssz_derive;

use ssz::{Decode, Encode};

use types::{BeaconState, MainnetEthSpec};

use std::fs::File;
use std::io;
use std::io::Read;

use std::process;
use walkdir::WalkDir;

use std::fs::OpenOptions;
use std::io::prelude::*;

extern crate rand;
use rand::seq::SliceRandom;
use rand::thread_rng;

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

#[inline(always)]
fn fuzz_logging(path: &String) {
    // get the pid of the thread
    let pid = process::id();
    // open the logging file - usefull to find beaconstate file when one thread crash
    // PID of the crash thread is inside fuzzer-honggfuzz/hfuzz_workspace/TARGET/HONGGFUZZ.REPORT.TXT
    let mut file = OpenOptions::new()
        .append(true)
        .create(true)
        .open("rust_hfuzz.log")
        .unwrap();
    // write info in the logging file
    if let Err(e) = writeln!(file, "pid: {} | beaconstate: {}", pid, path) {
        eprintln!("Couldn't write to file: {}", e);
    }
}

#[link(name = "pfuzz", kind = "static")]
extern "C" {
    fn PrysmMain(bls: bool);
}
#[link(name = "nfuzz", kind = "static")]
extern "C" {
    fn NimMain();
}

fn main() {
    // provide only valid beaconstate in this folder
    // valid ssz beaconstate here: ../../../corpora/mainnet/beaconstate/
    use std::env;
    let key = "ETH2FUZZ_BEACONSTATE";
    let mut beacon_path: String = "".to_string();
    match env::var(key) {
        Ok(val) => beacon_path = val,
        Err(e) => println!("couldn't interpret {}: {}", key, e),
    };
    let mut list_path = match list_files_in_folder(&beacon_path) {
        Ok(list_path) => list_path,
        Err(e) => panic!("list_files_in_folder failed: {:?}", e),
    };

    // shuffle the list of beaconstate files
    let mut rng = thread_rng();
    list_path.shuffle(&mut rng);

    // create empty path string
    let mut path: String = String::new();
    // create fake result with and Error
    let mut beaconstate: Result<BeaconState<MainnetEthSpec>, ssz::DecodeError> =
        Err(ssz::DecodeError::BytesInvalid("fake_error".to_string()));

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

    // Can't panic here since we have already check if
    // beaconstate.is_err()
    let state = beaconstate.unwrap();

    // get correct beaconstate as u8
    let beacon_blob = read_contents_from_path(&path).unwrap();

    // Initialize eth2client environment
    unsafe {
        PrysmMain(false);
        NimMain();
    }

    // Run fuzzing loop
    loop {
        fuzz!(|data| {
            // SSZ Decoding of the container depending of the type
            if let Ok(att) = lighthouse::ssz_voluntary_exit(&data) {
                // clone the beaconstate locally
                let beacon_clone = state.clone();

                // call lighthouse and get post result
                // focus only on valid post here
                if let Ok(post) = lighthouse::process_voluntary_exit(beacon_clone, att.clone()) {
                    // call prysm
                    let res = prysm::process_voluntary_exit(
                        &beacon_blob, //target.pre.as_ssz_bytes(),
                        &data,        //target.attestation.as_ssz_bytes(),
                        &post.as_ssz_bytes(),
                    );
                    assert_eq!(res, true);

                    // call nimbus
                    let res = nimbus::process_voluntary_exit(
                        &state.clone(), //target.pre.as_ssz_bytes(),
                        &att,           //target.attestation.as_ssz_bytes(),
                        &post.as_ssz_bytes(),
                    );
                    assert_eq!(res, true);
                } else {
                    // we assert that we should get false
                    // as return value because lighthouse process
                    // returned an error
                    let res = prysm::process_voluntary_exit(
                        &beacon_blob, //target.pre.as_ssz_bytes(),
                        &data,        //target.attestation.as_ssz_bytes(),
                        &[],          // we don't care of the value here
                                      // because prysm should reject
                                      // the module first
                    );
                    assert_eq!(res, false);

                    // we assert that we should get false
                    // as return value because lighthouse process
                    // returned an error
                    let res = nimbus::process_voluntary_exit(
                        &state.clone(), //target.pre.as_ssz_bytes(),
                        &att,           //target.attestation.as_ssz_bytes(),
                        &[],
                    );
                    assert_eq!(res, false);
                }
            // Invalid SSZ container
            } else {
                // data is an invalid ssz
                // we need to verify it is detected as well by other
                // eth2client

                // we assert that we should get false as return value
                // because the ssz data is incorrect for lighthouse
                let res = prysm::process_voluntary_exit(
                    &beacon_blob, //target.pre.as_ssz_bytes(),
                    &data,        //target.attestation.as_ssz_bytes(),
                    &[],          // we don't care of the value here
                                  // because prysm should reject
                                  // the module first
                );
                assert_eq!(res, false);

                // TODO for nimbus
            }
        })
    }
}
