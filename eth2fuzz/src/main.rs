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
use std::env as real_env;
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
// load go fuzzers
mod go_fuzzers;
// load go fuzzers
mod java_fuzzers;

/// Run eth2fuzz fuzzing targets
#[derive(StructOpt, Debug)]
enum Cli {
    /// Run all fuzz targets
    #[structopt(name = "continuously")]
    Continuous {
        /// Only run target containing this eth2 clients name (e.g. lighthouse)
        #[structopt(short = "q", long = "filter")]
        filter: String,
        /// Which fuzzer to run
        #[structopt(
            short = "f",
            long = "fuzzer",
            possible_values = &fuzzers::Fuzzer::variants(),
            case_insensitive = true
        )]
        fuzzer: Option<fuzzers::Fuzzer>,
        /// Set timeout per target (in seconds)
        #[structopt(short = "t", long = "timeout", default_value = "1800")]
        timeout: i32,
        /// Set number of thread
        #[structopt(short = "n", long = "thread")]
        thread: Option<i32>,
        /// Set seed value
        #[structopt(short = "s", long = "seed")]
        seed: Option<i32>,
        /// Set a compilation sanitizer (advanced)
        #[structopt(
            long = "sanitizer",
            possible_values = &fuzzers::Sanitizer::variants(),
            case_insensitive = true
        )]
        sanitizer: Option<fuzzers::Sanitizer>,
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
            short = "f",
            long = "fuzzer",
            possible_values = &fuzzers::Fuzzer::variants(),
            case_insensitive = true
        )]
        fuzzer: Option<fuzzers::Fuzzer>,
        /// Set timeout (in seconds)
        #[structopt(short = "t", long = "timeout")]
        timeout: Option<i32>,
        /// Set number of thread (only for hfuzz)
        #[structopt(short = "n", long = "thread")]
        thread: Option<i32>,
        /// Set seed value
        #[structopt(short = "s", long = "seed")]
        seed: Option<i32>,
        /// Set a compilation sanitizer (advanced)
        #[structopt(
            long = "sanitizer",
            possible_values = &fuzzers::Sanitizer::variants(),
            case_insensitive = true
        )]
        sanitizer: Option<fuzzers::Sanitizer>,
    },
    /// List all available targets
    #[structopt(name = "list")]
    ListTargets,
}

/// Main function catching errors
fn main() {
    if let Err(e) = run() {
        eprintln!("{}", e);
        for cause in e.iter_chain().skip(1) {
            eprintln!("caused by: {}", cause);
        }
        ::std::process::exit(1);
    }
}

enum Clients {
    Lighthouse,
    Nimbus,
    Prysm,
    Teku,
    Lodestar,
    All,
}

fn current_client() -> Clients {
    let key = "CURRENT_CLIENT";
    match real_env::var_os(key) {
        Some(a) => match a.to_str() {
            Some("LIGHTHOUSE") => Clients::Lighthouse,
            Some("NIMBUS") => Clients::Nimbus,
            Some("PRYSM") => Clients::Prysm,
            Some("TEKU") => Clients::Teku,
            Some("LODESTAR") => Clients::Lodestar,
            _ => panic!("CURRENT_CLIENT is invalid"),
        },
        None => Clients::All,
    }
}

/// Parsing of CLI arguments
fn run() -> Result<(), Error> {
    use Cli::*;
    let cli = Cli::from_args();

    match cli {
        // list all targets
        ListTargets => {
            list_targets()?;
        }
        // Fuzz one target
        Run {
            target,
            fuzzer,
            timeout,
            thread,
            seed,
            sanitizer,
        } => {
            let config = fuzzers::FuzzerConfig {
                timeout,
                thread,
                sanitizer,
                seed,
            };
            run_target(target, fuzzer, config)?;
        }
        // Fuzz multiple targets
        Continuous {
            filter,
            timeout,
            fuzzer,
            thread,
            seed,
            sanitizer,
            infinite,
        } => {
            let config = fuzzers::FuzzerConfig {
                timeout: Some(timeout),
                thread,
                sanitizer,
                seed,
            };
            run_continuously(Some(filter), fuzzer, config, infinite)?;
        }
    }
    Ok(())
}

/// List all targets available
fn list_targets() -> Result<(), Error> {
    let client = current_client();
    use Clients::*;
    let list_targets = match client {
        Lighthouse => targets::get_lighthouse_targets(),
        Nimbus => targets::get_nimbus_targets(),
        Prysm => targets::get_prysm_targets(),
        Teku => targets::get_teku_targets(),
        Lodestar => targets::get_lodestar_targets(),
        All => targets::get_targets(),
    };
    for target in list_targets {
        println!("{}", target);
    }
    Ok(())
}

/// Run fuzzing on only one target
fn run_target(
    target: String,
    fuzzer: Option<fuzzers::Fuzzer>,
    config: fuzzers::FuzzerConfig,
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

    // Find default fuzzer is nothing is defined by the user
    let default_fuzz = match fuzzer {
        Some(o) => o,
        None => fuzzers::get_default_fuzzer(target),
    };

    match default_fuzz {
        Afl => {
            let afl = rust_fuzzers::FuzzerAfl::new(config)?;
            afl.run(target)?;
        }
        Honggfuzz => {
            let hfuzz = rust_fuzzers::FuzzerHfuzz::new(config)?;
            hfuzz.run(target)?;
        }
        Libfuzzer => {
            let lfuzz = rust_fuzzers::FuzzerLibfuzzer::new(config)?;
            lfuzz.run(target)?;
        }
        Jsfuzz => {
            let jfuzz = js_fuzzers::FuzzerJsFuzz::new(config)?;
            jfuzz.run(target)?;
        }
        //NimAfl => {
        //    let nfuzz = nim_fuzzers::FuzzerNimAfl::new(config)?;
        //    nfuzz.run(target)?;
        //}
        NimLibfuzzer => {
            let nfuzz = nim_fuzzers::FuzzerNimLibfuzzer::new(config)?;
            nfuzz.run(target)?;
        }
        GoLibfuzzer => {
            let gofuzz = go_fuzzers::FuzzerGoLibfuzzer::new(config)?;
            gofuzz.run(target)?;
        }
        JavaJQFAfl => {
            let javafuzz = java_fuzzers::FuzzerJavaJQFAfl::new(config)?;
            javafuzz.run(target)?;
        }
    }
    Ok(())
}

/// Run fuzzing on multiple target matching the filter option
fn run_continuously(
    filter: Option<String>,
    fuzzer: Option<fuzzers::Fuzzer>,
    config: fuzzers::FuzzerConfig,
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

        // Find default fuzzer is nothing is defined by the user
        let default_fuzz = match fuzzer {
            Some(o) => o,
            None => fuzzers::get_default_fuzzer(target),
        };

        match default_fuzz {
            Afl => {
                let hfuzz = rust_fuzzers::FuzzerAfl::new(config)?;
                hfuzz.run(target)?;
            }
            Honggfuzz => {
                let hfuzz = rust_fuzzers::FuzzerHfuzz::new(config)?;
                hfuzz.run(target)?;
            }
            Libfuzzer => {
                let hfuzz = rust_fuzzers::FuzzerLibfuzzer::new(config)?;
                hfuzz.run(target)?;
            }
            Jsfuzz => {
                let jfuzz = js_fuzzers::FuzzerJsFuzz::new(config)?;
                jfuzz.run(target)?;
            }
            //NimAfl => {
            //    let nfuzz = nim_fuzzers::FuzzerNimAfl::new(config)?;
            //    nfuzz.run(target)?;
            //}
            NimLibfuzzer => {
                let nfuzz = nim_fuzzers::FuzzerNimLibfuzzer::new(config)?;
                nfuzz.run(target)?;
            }
            GoLibfuzzer => {
                let gofuzz = go_fuzzers::FuzzerGoLibfuzzer::new(config)?;
                gofuzz.run(target)?;
            }
            JavaJQFAfl => {
                let javafuzz = java_fuzzers::FuzzerJavaJQFAfl::new(config)?;
                javafuzz.run(target)?;
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
