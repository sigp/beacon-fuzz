extern crate structopt;
#[macro_use]
extern crate clap;
#[macro_use]
extern crate failure;

use failure::Error;
use structopt::StructOpt;

use ssz::Encode; //Decode

mod utils;

/// Run beaconfuzz_v2
#[derive(StructOpt, Debug)]
enum Cli {
    /// Run debug command
    #[structopt(name = "debug")]
    Debug {
        /// Pre-Beaconstate
        beaconstate_filename: String,
        /// Container
        container_filename: String,
        /// Container type
        #[structopt(
            possible_values = &self::Containers::variants(),
            case_insensitive = true
        )]
        container_type: Containers,
    },
    /// Run fuzzer
    #[structopt(name = "fuzz")]
    Fuzz {
        /// Set corpora path
        #[structopt(
            short = "f",
            long = "corpora",
            default_value = "../eth2fuzz/workspace/corpora"
        )]
        corpora: String,
        /// Which target to run
        #[structopt(
            possible_values = &self::Containers::variants(),
            case_insensitive = true
        )]
        container_type: Containers,
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
        Fuzz {
            corpora,
            container_type,
        } => {
            fuzz_target(corpora, container_type)?;
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

fn fuzz_target(corpora: String, container_type: Containers) -> Result<(), Error> {
    println!("[+] fuzz_target");
    println!("[+] corpora: {}", corpora);
    println!("[+] container_type: {:?}", container_type);
    Ok(())
}

fn run_attestation(beacon_blob: &[u8], container_blob: &[u8]) {
    // SSZ Decoding of the beaconstate
    let beacon = lighthouse::ssz_beaconstate(&beacon_blob).expect("beacon ssz decode failed");

    // SSZ Decoding of the container depending of the type
    let container =
        lighthouse::ssz_attestation(&container_blob).expect("container ssz decoding failed");

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
                &beacon_blob, //beacon &[u8]
                &data,        //container &[u8]
                &post.as_ssz_bytes(),
            );
            assert_eq!(res, true);

            println!("[DEBUG] NIMBUS: start");
            let res = nimbus::process_attestation(
                &state.clone(), //target.pre.as_ssz_bytes(),
                &att,           //target.attestation.as_ssz_bytes(),
                &post.as_ssz_bytes(),
            );
            assert_eq!(res, true);
        } else {
            // Lighthouse returned an error during container
            // processing meaning other client should do the same

            println!("[DEBUG] PRYSM: start");
            let res = prysm::process_attestation(
                &beacon_blob, //target.pre.as_ssz_bytes(),
                &data,        //target.attestation.as_ssz_bytes(),
                &[],          // we don't care of the value here
                              // because prysm should reject
                              // the module first
            );
            assert_eq!(res, false);

            println!("[DEBUG] NIMBUS: start");
            let res = nimbus::process_attestation(
                &state.clone(),
                &att,
                &[], // we don't care of the value here because prysm
                     // will reject the container before
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
            &beacon_blob,
            &data,
            &[], // we don't care of the value here because prysm
                 // will reject the container before
        );
        assert_eq!(res, false);

        // TODO for nimbus
    }
}

fn run_deposit(beacon_blob: &[u8], container_blob: &[u8]) {
    // SSZ Decoding of the beaconstate
    let beacon = lighthouse::ssz_beaconstate(&beacon_blob).expect("beacon ssz decode failed");

    let data = container_blob;
    let state = beacon;

    // SSZ Decoding of the container depending of the type
    if let Ok(att) = lighthouse::ssz_deposit(&data) {
        // clone the beaconstate locally
        let beacon_clone = state.clone();

        // call lighthouse and get post result
        // focus only on valid post here
        if let Ok(post) = lighthouse::process_deposit(beacon_clone, att.clone()) {
            println!("[LIGHTHOUSE]: {}", true);

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
            println!("[LIGHTHOUSE]: {}", false);
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

fn run_voluntary_exit(beacon_blob: &[u8], container_blob: &[u8]) {
    // SSZ Decoding of the beaconstate
    let beacon = lighthouse::ssz_beaconstate(&beacon_blob).expect("beacon ssz decode failed");

    let data = container_blob;
    let state = beacon;

    // SSZ Decoding of the container depending of the type
    if let Ok(att) = lighthouse::ssz_voluntary_exit(&data) {
        // clone the beaconstate locally
        let beacon_clone = state.clone();

        // call lighthouse and get post result
        // focus only on valid post here
        if let Ok(post) = lighthouse::process_voluntary_exit(beacon_clone, att.clone()) {
            println!("[LIGHTHOUSE]: {}", true);

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
            println!("[LIGHTHOUSE]: {}", false);
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
}

#[link(name = "pfuzz", kind = "static")]
extern "C" {
    fn PrysmMain(bls: bool);
}
#[link(name = "nfuzz", kind = "static")]
extern "C" {
    fn NimMain();
}

fn debug_target(
    beaconstate_filename: String,
    container_filename: String,
    container_type: Containers,
) -> Result<(), Error> {
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

    // Initialize eth2client environment
    unsafe {
        PrysmMain(false);
        NimMain();
    }

    match container_type {
        Containers::Attestation => {
            run_attestation(&beacon_blob, &container_blob);
        }
        Containers::Deposit => {
            run_deposit(&beacon_blob, &container_blob);
        }
        Containers::VoluntaryExit => {
            run_voluntary_exit(&beacon_blob, &container_blob);
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
