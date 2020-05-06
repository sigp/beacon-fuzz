#![allow(deprecated)]

extern crate structopt;
#[macro_use]
extern crate clap;
#[macro_use]
extern crate failure;
extern crate regex;

extern crate fs_extra;



use std::fs;
use std::path::PathBuf;
use std::process::Command;

use failure::{Error, ResultExt};

use structopt::StructOpt;

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
        /// Set timeout per target
        #[structopt(short = "t", long = "timeout", default_value = "10")]
        timeout: i32,
        // Run until the end of time (or Ctrl+C)
        #[structopt(short = "i", long = "infinite")]
        infinite: bool,
        /// Which fuzzer to run
        #[structopt(
            long = "fuzzer",
            default_value = "Honggfuzz",
            raw(possible_values = "&fuzzers::Fuzzer::variants()", case_insensitive = "true")
        )]
        fuzzer: fuzzers::Fuzzer,
        /// Set number of thread (only for hfuzz)
        #[structopt(short = "n", long = "thread")]
        thread: Option<i32>,
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
            raw(possible_values = "&fuzzers::Fuzzer::variants()", case_insensitive = "true")
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
        for cause in e.causes().skip(1) {
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
            for target in &fuzzers::get_targets()? {
                println!("{}", target);
            }
        }
        Run {
            target,
            fuzzer,
            timeout,
            thread,
        } => {
            let targets = fuzzers::get_targets()?;
            if targets.iter().find(|x| *x == &target).is_none() {
                bail!(
                    "Don't know target `{}`. {}",
                    target,
                    if let Some(alt) = did_you_mean(&target, &targets) {
                        format!("Did you mean `{}`?", alt)
                    } else {
                        "".into()
                    }
                );
            }

            use fuzzers::Fuzzer::*;
            match fuzzer {
                Afl => fuzzers::run_afl(&target, timeout, None)?, // TODO - fix thread
                Honggfuzz => fuzzers::run_honggfuzz(&target, timeout, thread)?,
                Libfuzzer => fuzzers::run_libfuzzer(&target, timeout, None)?, // TODO - fix thread
            }
        }
        Debug { target } => {
            let targets = fuzzers::get_targets()?;
            if targets.iter().find(|x| *x == &target).is_none() {
                bail!(
                    "Don't know target `{}`. {}",
                    target,
                    if let Some(alt) = did_you_mean(&target, &targets) {
                        format!("Did you mean `{}`?", alt)
                    } else {
                        "".into()
                    }
                );
            }

            run_debug(&target)?;
        }
        Continuous {
            filter,
            timeout,
            infinite,
            fuzzer,
            thread,
        } => {
            let run = |target: &str| -> Result<(), Error> {
                match fuzzer {
                    fuzzers::Fuzzer::Afl => fuzzers::run_afl(&target, Some(timeout), None)?, // TODO - fix thread
                    fuzzers::Fuzzer::Honggfuzz => fuzzers::run_honggfuzz(&target, Some(timeout), thread)?,
                    fuzzers::Fuzzer::Libfuzzer => fuzzers::run_libfuzzer(&target, Some(timeout), None)?, // TODO - fix thread
                }
                Ok(())
            };

            let targets = fuzzers::get_targets()?;
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
        }
    }
    Ok(())
}


fn prepare_debug_workspace(out_dir: &str) -> Result<(), Error> {
    let debug_init_dir = fuzzers::root_dir()?.join("debug");
    let dir = fuzzers::root_dir()?.join("workspace");

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

fn run_debug(target: &str) -> Result<(), Error> {
    let debug_dir = fuzzers::root_dir()?.join("workspace").join("debug");

    fuzzers::prepare_target_workspace()?;
    prepare_debug_workspace("debug")?;

    write_debug_target(debug_dir.clone(), target)?;

    let debug_bin = Command::new("cargo")
        .args(&["+nightly", "build", "--bin", &format!("debug_{}", target)])
        .current_dir(&debug_dir)
        .spawn()
        .context(format!("error starting {}", target))?
        .wait()
        .context(format!("error while waiting for {}", target))?;

    if !debug_bin.success() {
        Err(fuzzers::FuzzerQuit)?;
    }
    println!("[WARF] Debug: {} compiled", &format!("debug_{}", target));
    Ok(())
}

fn write_debug_target(debug_dir: PathBuf, target: &str) -> Result<(), Error> {
    use std::io::Write;

    // TODO - make it cleaner
    let template_path = fuzzers::root_dir()?.join("debug").join("debug_template.rs");
    let template = fs::read_to_string(&template_path).context(format!(
        "error reading debug template file {}",
        template_path.display()
    ))?;

    let target_dir = debug_dir.join("src").join("bin");
    fs::create_dir_all(&target_dir).context(format!(
        "error creating debug target dir {}",
        target_dir.display()
    ))?;
    let path = target_dir.join(&format!("debug_{}.rs", target));

    let mut file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&path)
        .context(format!(
            "error writing debug target binary {}",
            path.display()
        ))?;

    let source = template.replace("###TARGET###", &target);
    file.write_all(source.as_bytes())?;
    Ok(())
}


/// Produces a string from a given list of possible values which is similar to
/// the passed in value `v` with a certain confidence.
/// Thus in a list of possible values like ["foo", "bar"], the value "fop" will yield
/// `Some("foo")`, whereas "blark" would yield `None`.
///
/// Originally from [clap] which is Copyright (c) 2015-2016 Kevin B. Knapp
///
/// [clap]: https://github.com/kbknapp/clap-rs/blob/dc7ae65fb784dc355d56f09554f1216b22755c3e/src/suggestions.rs
pub fn did_you_mean<'a, T: ?Sized, I>(v: &str, possible_values: I) -> Option<&'a str>
where
    T: AsRef<str> + 'a,
    I: IntoIterator<Item = &'a T>,
{
    extern crate strsim;

    let mut candidate: Option<(f64, &str)> = None;
    for pv in possible_values {
        let confidence = strsim::jaro_winkler(v, pv.as_ref());
        if confidence > 0.8 && (candidate.is_none() || (candidate.as_ref().unwrap().0 < confidence))
        {
            candidate = Some((confidence, pv.as_ref()));
        }
    }
    match candidate {
        None => None,
        Some((_, candidate)) => Some(candidate),
    }
}
