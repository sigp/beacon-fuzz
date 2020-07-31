#[macro_use]
extern crate honggfuzz;

extern crate types;
extern crate walkdir;

extern crate ssz;
extern crate ssz_derive;

use ssz::{Decode, Encode};
use ssz_derive::{Decode, Encode};

use types::{Attestation, BeaconState, EthSpec, MainnetEthSpec};

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

use state_processing::{
    per_block_processing::{process_attestations, VerifySignatures},
    BlockProcessingError,
};

/*

LIGHTHOUSE

*/

/// Decode SSZ-encoded `Attestation` bytes
/// - input: SSZ-encoded bytes
/// - output: Ok(Attestation) or Err()
pub fn lighthouse_ssz_attestation(
    ssz_bytes: &[u8],
) -> Result<Attestation<MainnetEthSpec>, ssz::DecodeError> {
    Ok(Attestation::from_ssz_bytes(&ssz_bytes)?)
}

pub fn lighthouse_ssz_beaconstate(
    ssz_bytes: &[u8],
) -> Result<BeaconState<MainnetEthSpec>, ssz::DecodeError> {
    Ok(BeaconState::from_ssz_bytes(&ssz_bytes)?)
}

pub fn lighthouse_process_attestation(
    mut beaconstate: BeaconState<MainnetEthSpec>,
    attestation: Attestation<MainnetEthSpec>,
) -> Result<BeaconState<MainnetEthSpec>, BlockProcessingError> {
    let spec = MainnetEthSpec::default_spec();

    process_attestations(
        &mut beaconstate,
        &[attestation],
        VerifySignatures::True,
        &spec,
    )?;

    Ok(beaconstate)
}

/*

PRYSM

*/

#[link(name = "pfuzz", kind = "static")]
extern "C" {
    fn PrysmMain(bls: bool);
    fn pfuzz_attestation(
        beacon_ptr: *mut u8,
        beacon_size: usize,
        attest_ptr: *mut u8,
        attest_size: usize,
        out_ptr: *mut u8,
        out_size: usize,
    ) -> bool;
}

pub fn prysm_process_attestation(beacon: &[u8], attest: &[u8], post: &[u8]) -> Vec<u8> {
    //let out: Vec<u8> = Vec::with_capacity(post.len());
    let mut out: Vec<u8> = vec![0 as u8; post.len()];

    //println!("{:?}", beacon.as_ptr());
    //println!("{:?}", beacon.len());
    //println!("{:?}", out.as_ptr());
    //println!("{:?}", attest.len());

    let mut inn: Vec<u8> = beacon.into();
    let beacon_ptr: *mut u8 = inn.as_mut_ptr();
    let beacon_size: usize = beacon.len() as usize;
    let mut inn: Vec<u8> = attest.into();
    let attest_ptr: *mut u8 = inn.as_mut_ptr();
    //let attest_size: *mut usize = &mut (attest.len() as usize);
    let attest_size: usize = attest.len() as usize;

    //let mut inn: Vec<u8> = beacon.into();
    let out_prt: *mut u8 = out.as_mut_ptr();
    let out_size = post.len();

    let res = unsafe {
        // initialize nim gc memory, types and stack
        PrysmMain(false);

        pfuzz_attestation(
            beacon_ptr,
            beacon_size,
            attest_ptr,
            attest_size,
            out_prt,
            out_size,
        )
    };

    assert_eq!(out, post);
    println!("[good]: {}", res);
    out
}

/*

NIMBUS

*/

#[link(name = "nfuzz", kind = "static")]
extern "C" {
    fn NimMain();
    fn nfuzz_attestation(
        input_ptr: *mut u8,
        input_size: usize,
        output_ptr: *mut u8,
        output_size: *mut usize,
        disable_bls: bool,
    ) -> bool;
}

#[derive(Decode, Encode)]
struct AttestationTestCase {
    pub pre: BeaconState<MainnetEthSpec>,
    pub attestation: Attestation<MainnetEthSpec>,
}

pub fn nimbus_process_attestation(
    beacon: &BeaconState<MainnetEthSpec>,
    attest: &Attestation<MainnetEthSpec>,
    post: &[u8],
) -> Vec<u8> {
    // beacon: &[u8], attest: &[u8],
    //let out: Vec<u8> = Vec::with_capacity(post.len());
    let mut out: Vec<u8> = vec![0 as u8; post.len()];

    // create testcase ssz struct
    let target: AttestationTestCase = AttestationTestCase {
        pre: beacon.clone(),
        attestation: attest.clone(),
    };

    let ssz_bytes = target.as_ssz_bytes();

    println!("{:?}", ssz_bytes.as_ptr());
    println!("{:?}", ssz_bytes.len());
    println!("{:?}", out.as_ptr());
    println!("{:?}", post.len());

    let ssz_bytes_len = ssz_bytes.len();
    let mut inn: Vec<u8> = ssz_bytes.into();
    let input_ptr: *mut u8 = inn.as_mut_ptr();
    let input_size: usize = ssz_bytes_len as usize;
    let output_ptr: *mut u8 = out.as_mut_ptr();
    let output_size: *mut usize = &mut (post.len() as usize);

    let res = unsafe {
        // initialize nim gc memory, types and stack
        NimMain();

        nfuzz_attestation(input_ptr, input_size, output_ptr, output_size, false)
    };

    assert_eq!(out, post);
    println!("[good]: {}", res);
    out
}

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

    // Run fuzzing loop
    loop {
        fuzz!(|data| {
            if let Ok(att) = lighthouse_ssz_attestation(&data) {
                // clone the beaconstate locally
                let beacon_clone = state.clone();
                // call lighthouse
                // focus only on valid post here
                if let Ok(post) = lighthouse_process_attestation(beacon_clone, att.clone()) {
                    // call prysm
                    prysm_process_attestation(
                        &beacon_blob, //target.pre.as_ssz_bytes(),
                        &data,        //target.attestation.as_ssz_bytes(),
                        &post.as_ssz_bytes(),
                    );

                    // call nimbus
                    nimbus_process_attestation(
                        &state.clone(), //target.pre.as_ssz_bytes(),
                        &att,           //target.attestation.as_ssz_bytes(),
                        &post.as_ssz_bytes(),
                    );
                }
            }
        })
    }
}
