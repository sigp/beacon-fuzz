#[macro_use]
extern crate failure;
extern crate structopt;

mod lighthouse;
mod utils;

/*

ROADMAP

- read beaconstate
- read attestation

- lighthouse beaconstate loading
- lighthouse attestation loading


Question?
possible to compare ssz parsing result?
- comparaison each field output structure?
- need to create getter function?


*/

use types::{Attestation, BeaconState, EthSpec, MainnetEthSpec};

//use serde::{Deserialize, Serialize};

fn test_lighthouse() {}

fn info_attestation(attest: &Attestation<MainnetEthSpec>) {
    // access containers info
    println!("{}", attest.aggregation_bits.len());
    println!("{}", attest.signature.as_bytes().len());
}

fn main() {
    println!("Hello, world!");

    let beacon = utils::read_from_path(&"beacon.ssz".to_string()).expect("beacon not here");
    println!("len beacon = {}", beacon.len());
    let attest = utils::read_from_path(&"attest.ssz".to_string()).expect("attest not here");
    println!("len attest = {}", attest.len());

    // ssz parsing
    let b = lighthouse::ssz_beaconstate(&beacon).expect("beacon ssz decode failed");
    let a = lighthouse::ssz_attestation(&attest).expect("attest ssz decode failed");

    // debug
    info_attestation(&a);
    //println!("len a = {}", bincode::serialize(&a).unwrap().len());

    // process
    let post = lighthouse::process_attestation(b, a).expect("process failed");

    //post_state.as_ssz_bytes();
}

/// Generate a bug report
/// when result of differential fuzzing is different
fn create_bug_report() {
    // TODO
}
