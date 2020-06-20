use failure::{Error, ResultExt};
use std::env;
use std::path::PathBuf;
use std::process::Command;

use crate::env::{corpora_dir, state_dir};
use crate::fuzzers::{FuzzerConfig, FuzzerQuit};
use crate::targets::Targets;

/***********************************************
name: jsfuzz
github: https://github.com/fuzzitdev/jsfuzz
***********************************************/

static LANGUAGE: &str = "js";

pub struct FuzzerJsFuzz {
    /// Fuzzer name.
    pub name: String,
    /// Source code / template dir
    pub dir: PathBuf,
    /// Workspace dir
    pub work_dir: PathBuf,
    /// fuzzing config
    pub config: FuzzerConfig,
}

impl FuzzerJsFuzz {
    /// Check if jsfuzz is installed
    fn is_available() -> Result<(), Error> {
        println!("[eth2fuzz] Testing FuzzerJsFuzz is available");
        let fuzzer_output = Command::new("jsfuzz").arg("--version").output()?;

        if !fuzzer_output.status.success() {
            bail!("jsfuzz not available, install with `npm i -g jsfuzz`");
        }
        Ok(())
    }

    /// Create a new FuzzerJsFuzz
    pub fn new(config: FuzzerConfig) -> Result<FuzzerJsFuzz, Error> {
        // Test if fuzzer engine installed
        FuzzerJsFuzz::is_available()?;
        let cwd = env::current_dir().context("error getting current directory")?;

        // Create the fuzzer
        let fuzzer = FuzzerJsFuzz {
            name: "JsFuzz".to_string(),
            dir: cwd.join("fuzzers").join("js-jsfuzz"),
            work_dir: cwd.join("workspace").join("jsfuzz"),
            config,
        };
        Ok(fuzzer)
    }

    /// Run the fuzzer for the given target
    pub fn run(&self, target: Targets) -> Result<(), Error> {
        // check if target is supported by this fuzzer
        if target.language() != LANGUAGE {
            bail!(format!("{} incompatible for this target", self.name));
        }

        // get corpora dir of the target
        let corp_dir = corpora_dir()?.join(target.corpora()); //.join("*");

        // handle fuzzing options
        if self.config.timeout != None {
            println!("[eth2fuzz] {}: timeout not supported", self.name);
        }
        if self.config.thread != None {
            println!("[eth2fuzz] {}: thread not supported", self.name);
        }
        if self.config.sanitizer != None {
            println!("[eth2fuzz] {}: sanitizer not supported", self.name);
        }

        println!("[eth2fuzz] Starting {} for {}", self.name, target.name());

        // Run the fuzzer
        let fuzzer_bin = Command::new("jsfuzz")
            // beaconstate folder
            .env(
                "ETH2FUZZ_BEACONSTATE",
                format!("{}", state_dir()?.display()),
            )
            // target
            .arg(format!("{}.js", target.name()))
            // corpora
            .arg(corp_dir)
            .current_dir(&self.work_dir)
            .spawn()
            .context(format!(
                "error starting {} to run {}",
                self.name,
                target.name()
            ))?
            .wait()
            .context(format!(
                "error while waiting for {} running {}",
                self.name,
                target.name()
            ))?;

        // Check fuzzer success
        if !fuzzer_bin.success() {
            return Err(FuzzerQuit.into());
        }
        Ok(())
    }
}
