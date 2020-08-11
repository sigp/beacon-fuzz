#[macro_use]
extern crate failure;

extern crate structopt;

extern crate strum;
extern crate strum_macros;

extern crate chrono;
use chrono::offset::Utc;
use chrono::DateTime;

extern crate walkdir;
use walkdir::WalkDir;

use std::env;
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Output};

use failure::{Error, ResultExt};
use structopt::StructOpt;
//use strum::IntoEnumIterator;
use clap::arg_enum;
use strum_macros::EnumIter; // etc.

use colored::*; // color terminal stdout

/// eth2diff - Differential testing for eth2-clients tools.
#[derive(StructOpt, Debug)]
enum Cli {
    /// Run a state-transition
    #[structopt(name = "transition")]
    Transition {
        /// Pre-state (Input) path
        beaconstate: String,
        /// block (Input) path
        block: String,
        // TODO - add choice eth2-clients?
    },
    /// Test all file in corpora
    #[structopt(name = "transition_corpora")]
    TransitionCorpora {
        /// Pre-state (Input) path
        beaconstate_path: String,
        /// block (Input) path
        block_path: String,
        /// Numbre of thread
        #[structopt(short = "n", long = "thread", default_value = "4")]
        thread: i32,
        /// verbose
        #[structopt(short = "v", long = "verbose")]
        verbose: bool,
        // TODO - add choice eth2-clients?
    },
    /// Pretty-print SSZ data
    #[structopt(name = "pretty")]
    Pretty {
        /// SSZ Container Type (e.g. Attestation)
        #[structopt(possible_values = &SSZContainer::variants(), case_insensitive = true)]
        ssztype: SSZContainer,
        /// Input path
        input: String,
    },
    /// Hash tree root SSZ data
    #[structopt(name = "hash_tree_root")]
    HashTreeRoot {
        /// SSZ Container Type (e.g. Attestation)
        #[structopt(possible_values = &SSZContainer::variants(), case_insensitive = true)]
        ssztype: SSZContainer,
        /// Input path
        input: String,
    },
}

fn run() -> Result<(), Error> {
    use Cli::*;
    let cli = Cli::from_args();

    match cli {
        Transition { beaconstate, block } => {
            state_transition(beaconstate, block)?;
        }
        TransitionCorpora {
            beaconstate_path,
            block_path,
            thread,
            verbose,
        } => {
            process_corpora(beaconstate_path, block_path, thread, verbose)?;
        }
        Pretty { ssztype, input } => {
            pretty(ssztype, input)?;
        }
        HashTreeRoot { ssztype, input } => {
            hash_tree_root(ssztype, input)?;
        }
    }
    Ok(())
}

fn main() {
    if let Err(e) = run() {
        eprintln!("{}", e);
        for cause in e.iter_chain() {
            eprintln!("[-] Exited: {}", cause);
        }
        ::std::process::exit(1);
    }
}
arg_enum! {
    #[derive(StructOpt, Debug, Clone, Copy, PartialEq, Eq, EnumIter)]
    enum SSZContainer {
        Attestation,
        AttestationData,
        AttesterSlashing,
        BeaconBlock,
        BeaconBlockBody,
        BlockHeader,
        Deposit,
        DepositData,
        DepositMessage,
        Eth1Data,
        ForkData,
        ProposerSlashing,
        SignedBeaconBlock,
        SignedBlockHeader,
        SignedVoluntaryExit,
        BeaconState,
        VoluntaryExit,
    }
}

impl SSZContainer {
    /// containers name
    fn name(&self) -> String {
        match self {
            Self::Attestation => "attestation".to_string(),
            Self::AttestationData => "attestation_data".to_string(),
            Self::AttesterSlashing => "attester_slashing".to_string(),
            Self::BeaconBlock => "block".to_string(),
            Self::BeaconBlockBody => "block_body".to_string(),
            Self::BlockHeader => "block_header".to_string(),
            Self::Deposit => "deposit".to_string(),
            Self::DepositData => "deposit_data".to_string(),
            Self::DepositMessage => "deposit_message".to_string(),
            Self::Eth1Data => "eth1_data".to_string(),
            Self::ForkData => "fork_data".to_string(),
            Self::ProposerSlashing => "proposer_slashing".to_string(),
            Self::SignedBeaconBlock => "signed_block".to_string(),
            Self::SignedBlockHeader => "signed_block_header".to_string(),
            Self::SignedVoluntaryExit => "signed_voluntary_exit".to_string(),
            Self::BeaconState => "state".to_string(),
            //Self::APIBeaconState => "".to_string(),
            Self::VoluntaryExit => "voluntary_exit".to_string(),
        }
    }
}

pub struct Eth2Client {
    /// eth2-client print name.
    pub name: String,
    /// Path of compiled eth2client tool.
    pub cmd_path: PathBuf,
    /// Argument of compiled eth2client tool.
    pub cmd_arg: Vec<String>,
    /// cmd output
    pub output: Option<Output>,
    // Only status code
    pub status_code: Option<i32>,
    /// eth2client is available inside shared folder.
    available: bool,
}

impl Eth2Client {
    /// Create a new Eth2Client and check if binary is available
    pub fn new(name: String, cmd_path: PathBuf, cmd_arg: Vec<String>) -> Eth2Client {
        let available = cmd_path.exists();
        Eth2Client {
            name,
            cmd_path,
            cmd_arg,
            output: None,
            status_code: None,
            available,
        }
    }

    pub fn run_cmd(&mut self) -> Result<(), Error> {
        if !self.available {
            bail!("[X] Not available".red())
        }
        println!(
            "[+] Command: {} {}",
            self.cmd_path.file_name().unwrap().to_str().unwrap(),
            self.cmd_arg.join(" ")
        );
        let output = Command::new(&self.cmd_path).args(&self.cmd_arg).output()?;
        self.status_code = output.status.code();
        self.output = Some(output);
        Ok(())
    }

    pub fn log_stderr(&self) -> Result<(), Error> {
        if let Some(out) = self.output.clone() {
            //if let Some(stderr) = out.stderr {
            let string = String::from_utf8(out.stderr).unwrap();
            println!("[+] {}", string);
        //}
        } else {
            bail!("[X] No output".red());
        }
        Ok(())
    }

    pub fn log_stdout(&self) -> Result<(), Error> {
        if let Some(out) = self.output.clone() {
            //if let Some(stderr) = out.stderr {
            let string = String::from_utf8(out.stdout).unwrap();
            println!("[+] {}", string);
        //}
        } else {
            bail!("[X] No output".red());
        }
        Ok(())
    }

    pub fn log(&self) -> Result<(), Error> {
        //self.log_stderr()?;
        //self.log_stdout()?;
        self.log_status()?;
        Ok(())
    }

    fn log_status(&self) -> Result<(), Error> {
        if let Some(code) = &self.status_code {
            let message = format!("[+] Exited with status code: {}\n", code);
            match code {
                0 => println!("{}", message.green()),
                _ => println!("{}", message.red()),
            };
        } else {
            println!("{}", "[+] Process terminated by signal\n".red());
        }
        Ok(())
    }
}

fn create_report(eth2clients: &[Eth2Client]) -> Result<(), Error> {
    let cwd = env::current_dir().context("Error getting current directory")?;

    // Create crash dir
    let crashdir = cwd.join("shared").join("crashes");
    fs::create_dir_all(&crashdir)
        .context(format!("Unable to create {} dir", crashdir.display()))?;

    // Get report template content
    let template_path = cwd.join("shared").join("report_template.md");
    let template = fs::read_to_string(&template_path).context(format!(
        "error reading report template file {}",
        template_path.display()
    ))?;

    // Create report name
    let now: DateTime<Utc> = Utc::now();
    let report_name = format!("report_eth2diff_{}.md", now,);
    let path = crashdir.join(report_name);

    // Create report file
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&path)
        .context(format!(
            "error writing exec_all target binary {}",
            path.display()
        ))?;

    // replace ???DIFF_RESULT??? inside report template
    let mut results = String::new();
    for client in eth2clients.iter() {
        // stdout
        let cmd = format!(
            "{} {}",
            client.cmd_path.file_name().unwrap().to_str().unwrap(),
            client.cmd_arg.join(" ")
        );
        // diff results
        results.push_str(&format!("#{} -> {:?}\n", client.name, client.status_code));

        // details
        results.push_str(&format!("$ {}\n\n", cmd));
        //if let Some(out) = client.output.clone() {
        //let stdout = String::from_utf8(out.stdout).unwrap();
        //results.push_str(&format!("{:?}\n", out.stdout));
        //let stderr = String::from_utf8(out.stderr).unwrap();
        //    results.push_str(&format!("{:?}\n", out.stderr));
        //}
        //results.push_str(&format!("\n\n"));
    }
    let source = template.replace("???DETAILS_RESULTS???", &results);
    file.write_all(source.as_bytes())?;

    Ok(())
}

/// Process eth2clients list and run commands
fn process_eth2clients(eth2clients: &mut std::vec::Vec<Eth2Client>) -> Result<(), Error> {
    for eth2_client in eth2clients.iter_mut() {
        println!("[+] {}", eth2_client.name);

        match eth2_client.run_cmd() {
            Ok(_) => eth2_client.log()?,
            Err(e) => println!("[-] {} failed: {}\n", eth2_client.name, e),
        };
    }
    Ok(())
}

/// Compare eth2clients status_code and create report if differents
fn compare_results(eth2clients: &[Eth2Client]) -> Result<(), Error> {
    let mut codes = eth2clients.iter().map(|client| client.status_code);

    // all return 0 or 1
    if codes.all(|x| x == Some(0)) || codes.all(|x| x == Some(1)) {
        println!("{}", "[X] ALL GOOD\n".green());
        return Ok(());
    }

    create_report(&eth2clients)?;
    println!("{}", "[X] STATUS CODE ARE DIFFERENT\n".red());
    Ok(())
}

fn pretty(ssztype: SSZContainer, input: String) -> Result<(), Error> {
    let mut eth2_clients: Vec<Eth2Client> = Vec::new();
    let cwd = env::current_dir().context("[X] Error getting current directory")?;

    println!("== PRETTY ==");

    // ZCLI
    eth2_clients.push(Eth2Client::new(
        "ZCLI".into(),
        cwd.join("shared").join("zcli").join("zcli"),
        ["pretty".into(), ssztype.name(), input.to_owned()].to_vec(),
    ));

    // NIMBUS
    eth2_clients.push(Eth2Client::new(
        "NIMBUS".into(),
        cwd.join("shared").join("nimbus").join("ncli"),
        [
            "pretty".into(),
            format!("--prettyKind={}", ssztype.name()),
            format!("--prettyFile={}", input),
        ]
        .to_vec(),
    ));

    // PRYSM
    eth2_clients.push(Eth2Client::new(
        "PRYSM".into(),
        cwd.join("shared").join("prysm").join("pcli"),
        [
            "pretty".into(),
            "--ssz-path".into(),
            input,
            "--data-type".into(),
            ssztype.name(),
        ]
        .to_vec(),
    ));

    // run all eth2clients
    process_eth2clients(&mut eth2_clients)?;

    // compare the result
    compare_results(&eth2_clients)?;

    Ok(())
}

fn hash_tree_root(ssztype: SSZContainer, input: String) -> Result<(), Error> {
    let mut eth2_clients: Vec<Eth2Client> = Vec::new();
    let cwd = env::current_dir().context("[X] Error getting current directory")?;

    println!("== HASH TREE ROOT ==");

    // ZCLI
    eth2_clients.push(Eth2Client::new(
        "ZCLI".into(),
        cwd.join("shared").join("zcli").join("zcli"),
        ["hash-tree-root".into(), ssztype.name(), input.to_owned()].to_vec(),
    ));

    // NIMBUS
    eth2_clients.push(Eth2Client::new(
        "NIMBUS".into(),
        cwd.join("shared").join("nimbus").join("ncli"),
        [
            "hashTreeRoot".into(),
            format!("--htrKind={}", ssztype.name()),
            format!("--htrFile={}", input),
        ]
        .to_vec(),
    ));

    // run all eth2clients
    process_eth2clients(&mut eth2_clients)?;

    // compare the result
    compare_results(&eth2_clients)?;

    Ok(())
}

fn state_transition(beaconstate: String, block: String) -> Result<(), Error> {
    let mut eth2_clients: Vec<Eth2Client> = Vec::new();
    let cwd = env::current_dir().context("[X] Error getting current directory")?;

    println!("== TRANSITION ==");
    // ZCLI
    eth2_clients.push(Eth2Client::new(
        "ZCLI".into(),
        cwd.join("shared").join("zcli").join("zcli"),
        [
            "transition".into(),
            "blocks".into(),
            "--pre".into(),
            beaconstate.to_owned(),
            block.to_owned(),
        ]
        .to_vec(),
    ));

    // NIMBUS

    eth2_clients.push(Eth2Client::new(
        "NIMBUS".into(),
        cwd.join("shared").join("nimbus").join("ncli"),
        [
            "transition".into(),
            format!("--preState={}", beaconstate),
            format!("--blck={}", block),
            "--postState=/dev/null".into(),
        ]
        .to_vec(),
    ));

    // LIGHTHOUSE
    eth2_clients.push(Eth2Client::new(
        "LIGHTHOUSE".into(),
        cwd.join("shared").join("lighthouse").join("lcli"),
        [
            "--spec".into(),  // needed?
            "mainnet".into(), // needed?
            "transition-blocks".into(),
            beaconstate.to_owned(),
            block.to_owned(),
        ]
        .to_vec(),
    ));

    // TEKU
    eth2_clients.push(Eth2Client::new(
        "TEKU".into(),
        cwd.join("shared").join("teku").join("bin").join("teku"),
        [
            "transition".into(),
            "blocks".into(),
            format!("--pre={}", beaconstate),
            block.to_owned(),
            "--network=mainnet".into(),
        ]
        .to_vec(),
    ));

    // PRYSM
    eth2_clients.push(Eth2Client::new(
        "PRYSM".into(),
        cwd.join("shared").join("prysm").join("pcli"),
        [
            "state-transition".into(),
            "--pre-state-path".into(),
            beaconstate,
            "--block-path".into(),
            block,
        ]
        .to_vec(),
    ));

    // run all eth2clients
    process_eth2clients(&mut eth2_clients)?;

    // compare the result
    compare_results(&eth2_clients)?;

    Ok(())
}

fn list_files_in_folder(path_str: &str) -> Result<Vec<String>, ()> {
    let mut list: Vec<String> = Vec::<String>::new();

    for entry in WalkDir::new(path_str).into_iter().filter_map(|e| e.ok()) {
        if entry.metadata().unwrap().is_file() {
            //println!("{}", entry.path().display());
            list.push(entry.path().display().to_string());
        }
    }
    Ok(list)
}

fn process_corpora(
    state_path: String,
    block_path: String,
    _thread: i32,
    _verbose: bool,
) -> Result<(), Error> {
    // Import the Pipeline trait to give all Iterators and IntoIterators the

    // .with_threads() method:

    // list of beaconstate files
    let state_list = match list_files_in_folder(&state_path) {
        Ok(list_path) => list_path,
        Err(e) => panic!("list_files_in_folder failed: {:?}", e),
    };

    // list of block files
    let block_list = match list_files_in_folder(&block_path) {
        Ok(list_path) => list_path,
        Err(e) => panic!("list_files_in_folder failed: {:?}", e),
    };

    for state in &state_list {
        for block in &block_list {
            let _ = state_transition(state.to_string(), block.to_string());
        }
    }

    println!("{:?}", state_list);

    Ok(())
}
