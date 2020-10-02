use failure::{Error, ResultExt};
use std::env;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

use crate::env::{corpora_dir, state_dir};
use crate::fuzzers::{FuzzerConfig, FuzzerQuit};
use crate::targets::Targets;

/***********************************************
name: libfuzzer for Go using go114-fuzz-build
github: https://github.com/mdempsky/go114-fuzz-build
***********************************************/

static LANGUAGE: &str = "go";

pub struct FuzzerGoLibfuzzer {
    /// Fuzzer name.
    pub name: String,
    /// Source code / template dir
    pub dir: PathBuf,
    /// Workspace dir
    pub work_dir: PathBuf,
    /// fuzzing config
    pub config: FuzzerConfig,
}

impl FuzzerGoLibfuzzer {
    /// Check if libfuzzer is installed
    fn is_available() -> Result<(), Error> {
        println!("[eth2fuzz] Testing FuzzerGoLibfuzzer is available");
        let fuzzer_output = Command::new("bin/go114-fuzz-build").arg("-h").output()?;

        if fuzzer_output.status.code() != Some(0) {
            bail!("go114-fuzz-build not available, install with `go get -u github.com/mdempsky/go114-fuzz-build`");
        }
        Ok(())
    }

    /// Create a new FuzzerGoLibfuzzer
    pub fn new(config: FuzzerConfig) -> Result<FuzzerGoLibfuzzer, Error> {
        // Test if fuzzer engine installed
        FuzzerGoLibfuzzer::is_available()?;
        let cwd = env::current_dir().context("error getting current directory")?;

        // Create the fuzzer
        let fuzzer = FuzzerGoLibfuzzer {
            name: "gofuzz".to_string(),
            dir: cwd.join("fuzzers").join("gofuzz"),
            work_dir: cwd.join("workspace").join("gofuzz"),
            config,
        };
        Ok(fuzzer)
    }

    /// Method to convert target name to compliant Go exported identifiers
    fn some_kind_of_uppercase_first_letter(&self, s: &str) -> String {
        let mut c = s.chars();
        match c.next() {
            None => String::new(),
            Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
        }
    }

    /// Run the fuzzer for the given target
    pub fn run(&self, target: Targets) -> Result<(), Error> {
        // check if target is supported by this fuzzer
        if target.language() != LANGUAGE {
            bail!(format!("{} incompatible for this target", self.name));
        }

        // get corpora dir of the target
        let corpora_dir = corpora_dir()?.join(target.corpora());

        // cd /eth2fuzz/src/github.com/prysmaticlabs/prysm/
        // cp /eth2fuzz/workspace/gofuzz/lib.go .

        fs::copy(
            "/eth2fuzz/workspace/gofuzz/lib.go",
            "/eth2fuzz/src/github.com/prysmaticlabs/prysm/lib.go",
        )?;

        // eth2fuzz/bin/go114-fuzz-build -func FuzzBlockHeader github.com/prysmaticlabs/prysm

        let compile_lib = Command::new("/eth2fuzz/bin/go114-fuzz-build")
            .args(&[
                "-tags=blst_enabled,libfuzzer",
                &self.some_kind_of_uppercase_first_letter(&target.name()),
                "github.com/prysmaticlabs/prysm",
            ])
            .current_dir("/eth2fuzz/src/github.com/prysmaticlabs/prysm/")
            .spawn()
            .context(format!(
                "error compilation {} to run {}",
                self.name,
                target.name()
            ))?
            .wait()
            .context(format!(
                "error while waiting for {} running {}",
                self.name,
                target.name()
            ))?;

        // Check compile success
        if !compile_lib.success() {
            return Err(FuzzerQuit.into());
        }

        // cp prysm-fuzz.a /eth2fuzz/workspace/gofuzz/

        fs::copy(
            "/eth2fuzz/src/github.com/prysmaticlabs/prysm/prysm-fuzz.a",
            "/eth2fuzz/workspace/gofuzz/prysm-fuzz.a",
        )?;

        // cd /eth2fuzz/workspace/gofuzz/
        // clang -fsanitize=fuzzer prysm-fuzz.a /eth2fuzz/src/github.com/herumi/bls-eth-go-binary/bls/lib/linux/amd64/libbls384_256.a -o prysm_FuzzBlockHeader.libfuzzer

        let compile_target = Command::new("clang")
            .args(&[
                "-fsanitize=fuzzer",
                "prysm-fuzz.a",
                "/eth2fuzz/src/github.com/herumi/bls-eth-go-binary/bls/lib/linux/amd64/libbls384_256.a",
                "-o",
                &format!("{}.libfuzzer", target.name()),
            ])
            //.arg(&format!("{}.{}", target.name(), target.language()))
            .current_dir(&self.work_dir)
            .spawn()
            .context(format!(
                "error compilation {} to run {}",
                self.name,
                target.name()
            ))?
            .wait()
            .context(format!(
                "error while waiting for {} running {}",
                self.name,
                target.name()
            ))?;

        // Check compile_target success
        if !compile_target.success() {
            return Err(FuzzerQuit.into());
        }

        // ETH2FUZZ_BEACONSTATE=/eth2fuzz/workspace/corpora/beaconstate ./prysm_FuzzBlockHeader.libfuzzer /eth2fuzz/workspace/corpora/block_header/

        // handle fuzzing config arguments
        // - timeout option
        let mut args: Vec<String> = Vec::new();
        if let Some(timeout) = self.config.timeout {
            args.push(format!("-max_total_time={}", timeout));
        };
        // - threading option
        if let Some(thread) = self.config.thread {
            args.push(format!("-workers={}", thread));
            args.push(format!("-jobs={}", thread));
        };
        // - seed option
        if let Some(seed) = self.config.seed {
            args.push(format!("-seed={}", seed));
        };
        args.push(format!("{}", &corpora_dir.display()));

        // Run the fuzzer
        let fuzzer_bin = Command::new(&format!("./{}.libfuzzer", target.name()))
            // beaconstate folder
            .env(
                "ETH2FUZZ_BEACONSTATE",
                format!("{}", state_dir()?.display()),
            )
            // fuzzing options
            .args(&args)
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
