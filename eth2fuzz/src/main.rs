extern crate regex;
extern crate structopt;
#[macro_use]
extern crate clap;
#[macro_use]
extern crate failure;

// Strum contains all the trait definitions
extern crate strum;
#[macro_use]
extern crate strum_macros;

use crate::strum::IntoEnumIterator;
use failure::Error;
use structopt::StructOpt;

// load fuzzers
mod env;
// load utily methods
mod utils;
// load targets
mod targets;
// load generic fuzzers stuff
mod fuzzers;
// load javascript fuzzers
mod js_fuzzers;
// load Nim fuzzers
mod nim_fuzzers;
// load rust fuzzers
mod rust_fuzzers;
// load debugging stuff
mod debug;

/// Run eth2fuzz fuzzing targets
#[derive(StructOpt, Debug)]
enum Cli {
    /// Run all fuzz targets
    #[structopt(name = "continuously")]
    Continuous {
        /// Only run target containing this string
        #[structopt(short = "q", long = "filter")]
        filter: Option<String>,
        /// Which fuzzer to run
        #[structopt(
            long = "fuzzer",
            default_value = "Honggfuzz",
            raw(
                possible_values = "&fuzzers::Fuzzer::variants()",
                case_insensitive = "true"
            )
        )]
        fuzzer: fuzzers::Fuzzer,
        /// Set timeout per target
        #[structopt(short = "t", long = "timeout", default_value = "10")]
        timeout: i32,
        /// Set number of thread (only for hfuzz)
        #[structopt(short = "n", long = "thread")]
        thread: Option<i32>,
        // Run until the end of time (or Ctrl+C)
        #[structopt(short = "i", long = "infinite")]
        infinite: bool,
    },
    /// Run one target with specific fuzzer
    #[structopt(name = "target")]
    Run {
        /// Which target to run
        target: String,
        /// Which fuzzer to run
        #[structopt(
            long = "fuzzer",
            default_value = "Honggfuzz",
            raw(
                possible_values = "&fuzzers::Fuzzer::variants()",
                case_insensitive = "true"
            )
        )]
        fuzzer: fuzzers::Fuzzer,
        /// Set timeout
        #[structopt(short = "t", long = "timeout")]
        timeout: Option<i32>,
        /// Set number of thread (only for hfuzz)
        #[structopt(short = "n", long = "thread")]
        thread: Option<i32>,
    },
    /// Debug one target
    #[structopt(name = "debug")]
    Debug {
        /// Which target to debug
        target: String,
    },
    /// List all available targets
    #[structopt(name = "list-targets")]
    ListTargets,
}

fn main() {
    if let Err(e) = run() {
        eprintln!("{}", e);
        for cause in e.iter_chain().skip(1) {
            eprintln!("caused by: {}", cause);
        }
        ::std::process::exit(1);
    }
}

fn run() -> Result<(), Error> {
    use Cli::*;
    let cli = Cli::from_args();

    match cli {
        ListTargets => {
            list_targets()?;
        }
        Run {
            target,
            fuzzer,
            timeout,
            thread,
        } => {
            run_target(target, fuzzer, timeout, thread)?;
        }
        Debug { target } => {
            debug::run_debug(target)?;
        }
        Continuous {
            filter,
            timeout,
            fuzzer,
            thread,
            infinite,
        } => {
            run_continuously(filter, fuzzer, Some(timeout), thread, infinite)?;
        }
    }
    Ok(())
}

fn list_targets() -> Result<(), Error> {
    for target in targets::get_targets() {
        println!("{}", target);
    }
    Ok(())
}

fn run_target(
    target: String,
    fuzzer: fuzzers::Fuzzer,
    timeout: Option<i32>,
    thread: Option<i32>,
) -> Result<(), Error> {
    let target = match targets::Targets::iter().find(|x| x.name() == target) {
        None => bail!(
            "Don't know target `{}`. {}",
            target,
            if let Some(alt) = utils::did_you_mean(&target, &targets::get_targets()) {
                format!("Did you mean `{}`?", alt)
            } else {
                "".into()
            }
        ),
        Some(t) => t,
    };

    use fuzzers::Fuzzer::*;
    match fuzzer {
        Afl => {
            let afl = rust_fuzzers::FuzzerAfl::new(timeout, None)?; // TODO - fix thread
            afl.run(target)?;
        }
        Honggfuzz => {
            let hfuzz = rust_fuzzers::FuzzerHfuzz::new(timeout, thread)?;
            hfuzz.run(target)?;
        }
        Libfuzzer => {
            let lfuzz = rust_fuzzers::FuzzerLibfuzzer::new(timeout, None)?; // TODO - fix thread
            lfuzz.run(target)?;
        }
        Jsfuzz => {
            let jfuzz = js_fuzzers::FuzzerJsFuzz::new(timeout, None)?;
            jfuzz.run(target)?;
        }
        NimAfl => {
            let nfuzz = nim_fuzzers::FuzzerNimAfl::new(timeout, None)?;
            nfuzz.run(target)?;
        }
        NimLibfuzzer => {
            let nfuzz = nim_fuzzers::FuzzerNimLibfuzzer::new(timeout, None)?;
            nfuzz.run(target)?;
        }
    }
    Ok(())
}

fn run_continuously(
    filter: Option<String>,
    fuzzer: fuzzers::Fuzzer,
    timeout: Option<i32>,
    thread: Option<i32>,
    infinite: bool,
) -> Result<(), Error> {
    let run = |target: &str| -> Result<(), Error> {
        let target = match targets::Targets::iter().find(|x| x.name() == target) {
            None => bail!(
                "Don't know target `{}`. {}",
                target,
                if let Some(alt) = utils::did_you_mean(&target, &targets::get_targets()) {
                    format!("Did you mean `{}`?", alt)
                } else {
                    "".into()
                }
            ),
            Some(t) => t,
        };

        use fuzzers::Fuzzer::*;
        match fuzzer {
            Afl => {
                let hfuzz = rust_fuzzers::FuzzerAfl::new(timeout, None)?; // TODO - fix thread
                hfuzz.run(target)?;
            }
            Honggfuzz => {
                let hfuzz = rust_fuzzers::FuzzerHfuzz::new(timeout, thread)?;
                hfuzz.run(target)?;
            }
            Libfuzzer => {
                let hfuzz = rust_fuzzers::FuzzerLibfuzzer::new(timeout, None)?; // TODO - fix thread
                hfuzz.run(target)?;
            }
            Jsfuzz => {
                let jfuzz = js_fuzzers::FuzzerJsFuzz::new(timeout, None)?;
                jfuzz.run(target)?;
            }
            NimAfl => {
                let nfuzz = nim_fuzzers::FuzzerNimAfl::new(timeout, None)?;
                nfuzz.run(target)?;
            }
            NimLibfuzzer => {
                let nfuzz = nim_fuzzers::FuzzerNimLibfuzzer::new(timeout, None)?;
                nfuzz.run(target)?;
            }
        }
        Ok(())
    };

    let targets = targets::get_targets();
    let targets = targets
        .iter()
        .filter(|x| filter.as_ref().map(|f| x.contains(f)).unwrap_or(true));

    'cycle: loop {
        'targets_pass: for target in targets.clone() {
            if let Err(e) = run(target) {
                match e.downcast::<fuzzers::FuzzerQuit>() {
                    Ok(_) => {
                        println!("Fuzzer failed so we'll continue with the next one");
                        continue 'targets_pass;
                    }
                    Err(other_error) => return Err(other_error),
                }
            }
        }

        if !infinite {
            break 'cycle;
        }
    }
    Ok(())
}
