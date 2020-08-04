extern crate structopt;
#[macro_use]
extern crate clap;
#[macro_use]
extern crate failure;

use failure::Error;
use structopt::StructOpt;

use ssz::Encode; //Decode

/*

ROADMAP

-- cli
-- read
*/

//mod lighthouse;
//use nimbus::process_attestation;
//use prysm::process_attestation;
mod utils;

/// Run beaconfuzz_v2
#[derive(StructOpt, Debug)]
enum Cli {
    /// Run debug command
    #[structopt(name = "debug")]
    Debug {
        /// Pre-Beaconstate
        beaconstate_filename: String,
        /// Which target to run
        container_filename: String,
        /// Type of the container
        #[structopt(
            possible_values = &self::Containers::variants(),
            case_insensitive = true
        )]
        container_type: Containers,
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
        Debug {
            beaconstate_filename,
            container_filename,
            container_type,
        } => {
            debug_target(beaconstate_filename, container_filename, container_type)?;
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
arg_enum! {
    #[derive(StructOpt, Debug)]
    enum Containers {
        Attestation,
        AttesterSlashing,
        Block,
        BlockHeader,
        Deposit,
        ProposerSlashing,
        VoluntaryExit,
    }
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
    println!("[+] List of available targets:");
    for cont in Containers::variants().iter() {
        println!("    {}", cont);
    }
    Ok(())
}

fn fuzz_target(_target: String, _corpora: String) -> Result<(), Error> {
    println!("[+] fuzz_target");
    Ok(())
}

fn run_attestation(beacon_blob: &[u8], container_blob: &[u8]) {
    // SSZ Decoding of the beaconstate
    let beacon = lighthouse::ssz_beaconstate(&beacon_blob).expect("beacon ssz decode failed");

    // SSZ Decoding of the container depending of the type
    let container =
        lighthouse::ssz_attestation(&container_blob).expect("container ssz decoding failed");

    // lighthouse processing
    let post = lighthouse::process_attestation(beacon.clone(), container).expect("process failed");

    let data = container_blob;
    let state = beacon;

    // test if lighthouse decode data properly
    // otherwise doesn't make sense to go deeper
    if let Ok(att) = lighthouse::ssz_attestation(&data) {
        // clone the beaconstate locally
        let beacon_clone = state.clone();

        // call lighthouse and get post result
        // focus only on valid post here
        println!("[DEBUG] LIGHTHOUSE: start");
        if let Ok(post) = lighthouse::process_attestation(beacon_clone, att.clone()) {
            println!("[DEBUG] LIGHTHOUSE: end");

            println!("[DEBUG] PRYSM: start");
            let res = prysm::process_attestation(
                &beacon_blob, //target.pre.as_ssz_bytes(),
                &data,        //target.attestation.as_ssz_bytes(),
                &post.as_ssz_bytes(),
            );
            assert_eq!(res, true);
            println!("[DEBUG] PRYSM: end");

            // call nimbus
            println!("[DEBUG] NIMBUS: start");
            let res = nimbus::process_attestation(
                &state.clone(), //target.pre.as_ssz_bytes(),
                &att,           //target.attestation.as_ssz_bytes(),
                &post.as_ssz_bytes(),
            );
            assert_eq!(res, true);
            println!("[DEBUG] NIMBUS: end");
        } else {
            // we assert that we should get false
            // as return value because lighthouse process
            // returned an error
            let res = prysm::process_attestation(
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
            let res = nimbus::process_attestation(
                &state.clone(), //target.pre.as_ssz_bytes(),
                &att,           //target.attestation.as_ssz_bytes(),
                &[],
            );
            assert_eq!(res, false);
        }
    } else {
        // data is an invalid ssz
        // we need to verify it is detected as well by other
        // eth2client

        // we assert that we should get false as return value
        // because the ssz data is incorrect for lighthouse
        let res = prysm::process_attestation(
            &beacon_blob, //target.pre.as_ssz_bytes(),
            &data,        //target.attestation.as_ssz_bytes(),
            &[],          // we don't care of the value here
                          // because prysm should reject
                          // the module first
        );
        assert_eq!(res, false);

        // TODO for nimbus
    }
}

fn run_deposit(beacon_blob: &[u8], container_blob: &[u8]) {
    // SSZ Decoding of the beaconstate
    let beacon = lighthouse::ssz_beaconstate(&beacon_blob).expect("beacon ssz decode failed");

    let data = container_blob;
    let state = beacon.clone();

    // SSZ Decoding of the container depending of the type
    if let Ok(att) = lighthouse::ssz_deposit(&data) {
        // clone the beaconstate locally
        let beacon_clone = state.clone();

        // call lighthouse and get post result
        // focus only on valid post here
        if let Ok(post) = lighthouse::process_deposit(beacon_clone, att.clone()) {
            // call prysm
            let res = prysm::process_deposit(
                &beacon_blob, //target.pre.as_ssz_bytes(),
                &data,        //target.attestation.as_ssz_bytes(),
                &post.as_ssz_bytes(),
            );
            assert_eq!(res, true);

            // call nimbus
            let res = nimbus::process_deposit(
                &state.clone(), //target.pre.as_ssz_bytes(),
                &att,           //target.attestation.as_ssz_bytes(),
                &post.as_ssz_bytes(),
            );
            assert_eq!(res, true);
        } else {
            // we assert that we should get false
            // as return value because lighthouse process
            // returned an error
            let res = prysm::process_deposit(
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
            let res = nimbus::process_deposit(
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
        let res = prysm::process_deposit(
            &beacon_blob, //target.pre.as_ssz_bytes(),
            &data,        //target.attestation.as_ssz_bytes(),
            &[],          // we don't care of the value here
                          // because prysm should reject
                          // the module first
        );
        assert_eq!(res, false);

        // TODO for nimbus
    }
}

fn debug_target(
    beaconstate_filename: String,
    container_filename: String,
    container_type: Containers,
) -> Result<(), Error> {
    //let _args: Vec<String> = env::args().collect();

    //let b = &args[1];
    //let b = beaconstate_path; //"beacon.ssz".to_string();
    //let a = &args[2];
    //let a = container_path; //"attest.ssz".to_string();

    // Read beaconstate ssz file
    println!("[DEBUG] beaconstate_path = {}", &beaconstate_filename);
    let beacon_blob = utils::read_from_path(&beaconstate_filename).expect("beacon not here");
    println!("[DEBUG] beaconstate length = {}", beacon_blob.len());

    // Read container ssz file
    println!("[DEBUG] container_path = {}", &container_filename);
    let container_blob = utils::read_from_path(&container_filename).expect("container not here");
    println!("[DEBUG] container length = {}", container_blob.len());

    // SSZ Decoding of the container depending of the type
    /*match container_type {
        Containers::Attestation => {
            lighthouse::ssz_attestation(&container_blob).expect("container ssz decoding failed")
        }
        Containers::AttesterSlashing => lighthouse::ssz_attester_slashing(&container_blob)
            .expect("container ssz decoding failed"),
        Containers::Block => {
            lighthouse::ssz_block(&container_blob).expect("container ssz decoding failed")
        }
        Containers::BlockHeader => {
            lighthouse::ssz_block_header(&container_blob).expect("container ssz decoding failed")
        }
        Containers::Deposit => {
            lighthouse::ssz_deposit(&container_blob).expect("container ssz decoding failed")
        }
        Containers::ProposerSlashing => lighthouse::ssz_proposer_slashing(&container_blob)
            .expect("container ssz decoding failed"),
        Containers::VoluntaryExit => {
            lighthouse::ssz_voluntary_exit(&container_blob).expect("container ssz decoding failed")
        }
    };*/

    match container_type {
        Containers::Attestation => {
            run_attestation(&beacon_blob, &container_blob);
        }
        Containers::Deposit => {
            run_deposit(&beacon_blob, &container_blob);
        }
        _ => panic!("not supported container yet"),
    }

    Ok(())
}

/// Generate a bug report
/// when result of differential fuzzing is different
fn _create_bug_report() {
    println!("TODO");
}
