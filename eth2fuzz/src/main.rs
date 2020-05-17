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

use failure::{Error, ResultExt};
use std::fs;
use std::path::PathBuf;
use std::process::Command;
use structopt::StructOpt;

// load fuzzers
mod env;
// load utily methods
mod utils;
// load targets
mod targets;
// load fuzzers
mod fuzzers;

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
            run_debug(target)?;
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
            let hfuzz = fuzzers::FuzzerAfl::new(timeout, None)?; // TODO - fix thread
            hfuzz.run(target)?;
        }
        Honggfuzz => {
            let hfuzz = fuzzers::FuzzerHfuzz::new(timeout, thread)?;
            hfuzz.run(target)?;
        }
        Libfuzzer => {
            let hfuzz = fuzzers::FuzzerLibfuzzer::new(timeout, None)?; // TODO - fix thread
            hfuzz.run(target)?;
        }
        Jsfuzz => {
            let jfuzz = fuzzers::FuzzerJsFuzz::new(timeout, None)?;
            jfuzz.run(target)?;
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
                let hfuzz = fuzzers::FuzzerAfl::new(timeout, None)?; // TODO - fix thread
                hfuzz.run(target)?;
            }
            Honggfuzz => {
                let hfuzz = fuzzers::FuzzerHfuzz::new(timeout, thread)?;
                hfuzz.run(target)?;
            }
            Libfuzzer => {
                let hfuzz = fuzzers::FuzzerLibfuzzer::new(timeout, None)?; // TODO - fix thread
                hfuzz.run(target)?;
            }
            Jsfuzz => {
                let jfuzz = fuzzers::FuzzerJsFuzz::new(timeout, None)?;
                jfuzz.run(target)?;
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
                    Err(other_error) => Err(other_error)?,
                }
            }
        }

        if !infinite {
            break 'cycle;
        }
    }
    Ok(())
}

fn prepare_debug_workspace(out_dir: &str) -> Result<(), Error> {
    let debug_init_dir = env::root_dir()?.join("debug");
    let dir = env::root_dir()?.join("workspace");

    let debug_dir = dir.join(out_dir);
    fs::create_dir_all(&debug_dir)
        .context(format!("unable to create {} dir", debug_dir.display()))?;

    let src_dir = debug_dir.join("src");
    fs::create_dir_all(&src_dir).context(format!("unable to create {} dir", src_dir.display()))?;

    fs::copy(
        debug_init_dir.join("Cargo.toml"),
        debug_dir.join("Cargo.toml"),
    )?;
    fs::copy(
        debug_init_dir.join("src").join("lib.rs"),
        src_dir.join("lib.rs"),
    )?;
    Ok(())
}

fn run_debug(target: String) -> Result<(), Error> {
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

    let debug_dir = env::root_dir()?.join("workspace").join("debug");

    fuzzers::prepare_targets_workspace()?;
    prepare_debug_workspace("debug")?;

    write_debug_target(debug_dir.clone(), target)?;

    let debug_bin = Command::new("cargo")
        .args(&[
            "+nightly",
            "build",
            "--bin",
            &format!("debug_{}", target.name()),
        ])
        .current_dir(&debug_dir)
        .spawn()
        .context(format!("error starting {}", target.name()))?
        .wait()
        .context(format!("error while waiting for {}", target.name()))?;

    if !debug_bin.success() {
        Err(fuzzers::FuzzerQuit)?;
    }
    println!(
        "[WARF] Debug: {} compiled",
        &format!("debug_{}", target.name())
    );
    Ok(())
}

fn write_debug_target(debug_dir: PathBuf, target: targets::Targets) -> Result<(), Error> {
    use std::io::Write;

    // TODO - make it cleaner
    let template_path = env::root_dir()?
        .join("debug")
        .join(format!("debug_{}", target.template()));
    let template = fs::read_to_string(&template_path).context(format!(
        "error reading debug template file {}",
        template_path.display()
    ))?;

    let target_dir = debug_dir.join("src").join("bin");
    fs::create_dir_all(&target_dir).context(format!(
        "error creating debug target dir {}",
        target_dir.display()
    ))?;
    let path = target_dir.join(&format!("debug_{}.rs", target.name()));

    let mut file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&path)
        .context(format!(
            "error writing debug target binary {}",
            path.display()
        ))?;

    let source = template.replace("###TARGET###", &target.name());
    file.write_all(source.as_bytes())?;
    Ok(())
}
