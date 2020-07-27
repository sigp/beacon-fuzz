extern crate structopt;
#[macro_use]
extern crate clap;
#[macro_use]
extern crate failure;

use failure::Error;
use std::env;
use structopt::StructOpt;

use ssz::Encode; //Decode
use ssz_derive::{Decode, Encode};

use types::{Attestation, BeaconState, MainnetEthSpec};

/*

ROADMAP

-- cli
-- read
*/

mod lighthouse;
mod nimbus;
mod prysm;
mod utils;

/// Run beaconfuzz_v2
#[derive(StructOpt, Debug)]
enum Cli {
    /// Run debug command
    #[structopt(name = "debug")]
    Debug {
        /// Which target to run
        target: String,
        /// Set corpora path
        #[structopt(
            short = "f",
            long = "corpora",
            default_value = "../eth2fuzz/workspace/corpora"
        )]
        corpora: String,
    },
    /// Run fuzzer
    #[structopt(name = "fuzz")]
    Fuzz {
        /// Which target to run
        target: String,
        /// Set corpora path
        #[structopt(
            short = "f",
            long = "corpora",
            default_value = "../eth2fuzz/workspace/corpora"
        )]
        corpora: String,
    },
    /// List all available fuzzing targets
    #[structopt(name = "list")]
    ListTargets,
}

/// Parsing of CLI arguments
fn run() -> Result<(), Error> {
    use Cli::*;
    let cli = Cli::from_args();

    match cli {
        // Fuzz one target
        Debug { target, corpora } => {
            debug_target(target, corpora)?;
        }
        // Fuzz targets
        Fuzz { target, corpora } => {
            fuzz_target(target, corpora)?;
        }
        // list all targets
        ListTargets => {
            list_targets()?;
        }
    }
    Ok(())
}

/// Main function catching errors
fn main() {
    println!("[+] beaconfuzz_v2");
    if let Err(e) = run() {
        eprintln!("[-] {}", e);
        for cause in e.iter_chain().skip(1) {
            eprintln!("[-] caused by: {}", cause);
        }
        ::std::process::exit(1);
    }
}

/// List all targets available
fn list_targets() -> Result<(), Error> {
    println!("[+] list targets");
    Ok(())
}

fn fuzz_target(_target: String, _corpora: String) -> Result<(), Error> {
    println!("[+] fuzz_target");
    Ok(())
}

// fn test_lighthouse() {}

fn info_attestation(attest: &Attestation<MainnetEthSpec>) {
    // access containers info
    println!("{}", attest.aggregation_bits.len());
    println!("{}", attest.signature.as_bytes().len());
}

fn debug_target(_target: String, _corpora: String) -> Result<(), Error> {
    let _args: Vec<String> = env::args().collect();

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
    info_attestation(&a);

    // lighthouse processing
    let post = lighthouse::process_attestation(b, a).expect("process failed");

    // nimbus processing
    //nimbus::process_attestation(
    //    &b, //target.pre.as_ssz_bytes(),
    //    &a,//target.attestation.as_ssz_bytes(),
    //    &post.as_ssz_bytes(),
    //);
    //post_state.as_ssz_bytes();

    prysm::process_attestation(
        &beacon, //target.pre.as_ssz_bytes(),
        &attest, //target.attestation.as_ssz_bytes(),
        &post.as_ssz_bytes(),
    );
    create_bug_report();
    prysm::process_attestation(
        &beacon, //target.pre.as_ssz_bytes(),
        &attest, //target.attestation.as_ssz_bytes(),
        &post.as_ssz_bytes(),
    );
    Ok(())
}

/// Generate a bug report
/// when result of differential fuzzing is different
fn create_bug_report() {
    println!("TODO");
}
