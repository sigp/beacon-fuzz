#[macro_use]
extern crate failure;
extern crate structopt;

use types::{Attestation, BeaconState, EthSpec, MainnetEthSpec};

use ssz::{Decode, Encode};
use ssz_derive::{Decode, Encode};

use std::env;

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

mod lighthouse;
mod nimbus;
mod utils;

fn test_lighthouse() {}

fn info_attestation(attest: &Attestation<MainnetEthSpec>) {
    // access containers info
    println!("{}", attest.aggregation_bits.len());
    println!("{}", attest.signature.as_bytes().len());
}

#[derive(Decode, Encode)]
struct AttestationTestCase {
    pub pre: BeaconState<MainnetEthSpec>,
    pub attestation: Attestation<MainnetEthSpec>,
}

fn main() {
    println!("[+] beaconfuzz_v2");

    let args: Vec<String> = env::args().collect();

    //let b = &args[1];
    let b = "beacon.ssz".to_string();
    //let a = &args[2];
    let a = "attest.ssz".to_string();

    // read files
    let beacon = utils::read_from_path(&b).expect("beacon not here");
    println!("length beacon = {}", beacon.len());
    let attest = utils::read_from_path(&a).expect("attest not here");
    println!("length attest = {}", attest.len());

    // ssz parsing
    let b = lighthouse::ssz_beaconstate(&beacon).expect("beacon ssz decode failed");
    let a = lighthouse::ssz_attestation(&attest).expect("attest ssz decode failed");

    // debug
    // info_attestation(&a);

    // create testcase ssz struct
    let target: AttestationTestCase = AttestationTestCase {
        pre: b.clone(),
        attestation: a.clone(),
    };

    // lighthouse processing
    let post = lighthouse::process_attestation(b, a).expect("process failed");

    // nimbus processing
    nimbus::process_attestation(&target.as_ssz_bytes(), &post.as_ssz_bytes());
    //post_state.as_ssz_bytes();
}

/// Generate a bug report
/// when result of differential fuzzing is different
fn create_bug_report() {
    // TODO
}
