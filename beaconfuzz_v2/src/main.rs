extern crate structopt;
#[macro_use]
extern crate clap;
#[macro_use]
extern crate failure;

use failure::Error;
use structopt::StructOpt;

use std::fs::File;
use std::io::Write;
use std::time::Instant;

mod rand;
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
    /// DO NOT USE - UNDER DEV
    #[structopt(name = "test")]
    Test {
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
        Test {
            corpora,
            container_type,
        } => {
            test(corpora, container_type)?;
        }
        // list all targets
        ListTargets => {
            list_targets()?;
        }
    }
    Ok(())
}
arg_enum! {
    #[derive(Copy, Clone, StructOpt, Debug)]
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

impl Containers {
    fn to_teku_FuzzTarget(self) -> teku::FuzzTarget {
        match self {
            Containers::Attestation => teku::FuzzTarget::Attestation,
            Containers::AttesterSlashing => teku::FuzzTarget::AttesterSlashing,
            Containers::Block => teku::FuzzTarget::Block,
            Containers::BlockHeader => teku::FuzzTarget::BlockHeader,
            Containers::Deposit => teku::FuzzTarget::Deposit,
            Containers::ProposerSlashing => teku::FuzzTarget::ProposerSlashing,
            Containers::VoluntaryExit => teku::FuzzTarget::VoluntaryExit,
        }
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

fn test(corpora: String, container_type: Containers) -> Result<(), Error> {
    // init random generator
    let mut rng = rand::Rng::new();

    println!("[+] fuzz_target");
    println!("[+] corpora: {}", corpora);
    println!("[+] container_type: {:?}", container_type);

    // Get the list of beacon files
    let beacon_folder = &format!("{}/{}", corpora, "beaconstate");
    let beacon_files = utils::list_files_in_folder(&beacon_folder).expect("no beacon files here");

    // Pick one random beacon file
    let index = rng.rand() % beacon_files.len();
    let beacon_blob = utils::read_from_path(&beacon_files[index]).expect("beacon not here");
    println!("[+] Beacon file: {}", &beacon_files[index]);

    // Get the list of container files
    let container_folder = &format!("{}/{}", corpora, "attestation");
    let container_files =
        utils::list_files_in_folder(&container_folder).expect("no container files here");

    // Pick one random Attestation to fuzz
    let index = rng.rand() % container_files.len();
    let container_blob =
        utils::read_from_path(&container_files[index]).expect("container not here");

    // Create log file
    // let mut outfd = File::create("log.txt").unwrap();

    // Initialize eth2client environment and disable bls
    eth2clientsfuzz::initialize_clients(true);

    // Call the fuzzing function
    // let it = Instant::now();

    /*
    for iters in 1u64.. {
        // Pick one random beacon file
        let index = rng.rand() % beacon_files.len();
        let beacon_blob = utils::read_from_path(&beacon_files[index]).expect("beacon not here");
        println!("[+] Beacon file: {}", &beacon_files[index]);

        // Pick one random Attestation to fuzz
        // TODO(optimization) - load contents in memory
        let index = rng.rand() % container_files.len();
        let container_blob =
            utils::read_from_path(&container_files[index]).expect("container not here");
        println!("[+] Container file: {}", &container_files[index]);

        // call the function
        eth2clientsfuzz::run_attestation(&beacon_blob, &container_blob);

        // stats monitoring
        if (iters & 0xff) == 0 {
            let elapsed = (Instant::now() - it).as_secs_f64();
            let cases_per_sec = iters as f64 / elapsed;
            writeln!(outfd, "cases/sec: {:12.4}", cases_per_sec)?;
        }
    }
    */

    eth2clientsfuzz::run_attestation_struct(&beacon_blob, &container_blob, true);

    Ok(())
}

fn fuzz_target(corpora: String, container_type: Containers) -> Result<(), Error> {
    // init random generator
    let mut rng = rand::Rng::new();

    println!("[+] fuzz_target");
    println!("[+] corpora: {}", corpora);
    println!("[+] container_type: {:?}", container_type);

    // Get the list of beacon files
    let beacon_folder = &format!("{}/{}", corpora, "beaconstate");
    let beacon_files = utils::list_files_in_folder(&beacon_folder).expect("no beacon files here");

    // Pick one random beacon file
    let index = rng.rand() % beacon_files.len();
    let beacon_blob = utils::read_from_path(&beacon_files[index]).expect("beacon not here");
    println!("[+] Beacon file: {}", &beacon_files[index]);

    // Get the list of container files
    let container_folder = &format!("{}/{}", corpora, "attestation");
    let container_files =
        utils::list_files_in_folder(&container_folder).expect("no container files here");

    // Pick one random Attestation to fuzz
    let index = rng.rand() % container_files.len();
    let container_blob =
        utils::read_from_path(&container_files[index]).expect("container not here");

    // Create log file
    let mut outfd = File::create("log.txt").unwrap();

    // Initialize eth2client environment and disable bls
    eth2clientsfuzz::initialize_clients(true);

    // Initialize teku
    teku::init_teku(true, container_type.to_teku_FuzzTarget());

    // Call the fuzzing function
    let it = Instant::now();

    for iters in 1u64.. {
        // Pick one random beacon file
        let index = rng.rand() % beacon_files.len();
        let beacon_blob = utils::read_from_path(&beacon_files[index]).expect("beacon not here");
        println!("[+] Beacon file: {}", &beacon_files[index]);

        // Pick one random Attestation to fuzz
        // TODO(optimization) - load contents in memory
        let index = rng.rand() % container_files.len();
        let container_blob =
            utils::read_from_path(&container_files[index]).expect("container not here");
        println!("[+] Container file: {}", &container_files[index]);

        // call the function
        eth2clientsfuzz::run_attestation(&beacon_blob, &container_blob);

        // stats monitoring
        if (iters & 0xff) == 0 {
            let elapsed = (Instant::now() - it).as_secs_f64();
            let cases_per_sec = iters as f64 / elapsed;
            writeln!(outfd, "cases/sec: {:12.4}", cases_per_sec)?;
        }
    }

    Ok(())
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

    // Initialize eth2client environment and disable bls
    eth2clientsfuzz::initialize_clients(true);

    // Initialize teku
    teku::init_teku(true, container_type.to_teku_FuzzTarget());

    // activate debug mode for nimbus and prysm
    // (print message when post mismatch + dump post state)
    eth2clientsfuzz::debug_clients(true);

    // SSZ processing of the container depending of the type
    match container_type {
        Containers::Attestation => {
            eth2clientsfuzz::run_attestation(&beacon_blob, &container_blob);
        }
        Containers::AttesterSlashing => {
            eth2clientsfuzz::run_attester_slashing(&beacon_blob, &container_blob);
        }
        Containers::Block => {
            eth2clientsfuzz::run_block(&beacon_blob, &container_blob);
        }
        Containers::BlockHeader => {
            eth2clientsfuzz::run_block_header(&beacon_blob, &container_blob);
        }
        Containers::Deposit => {
            eth2clientsfuzz::run_deposit(&beacon_blob, &container_blob);
        }
        Containers::ProposerSlashing => {
            eth2clientsfuzz::run_proposer_slashing(&beacon_blob, &container_blob);
        }
        Containers::VoluntaryExit => {
            eth2clientsfuzz::run_voluntary_exit(&beacon_blob, &container_blob);
        }
    }

    Ok(())
}

/// Generate a bug report
/// when result of differential fuzzing is different
fn _create_bug_report() {
    println!("TODO");
}
