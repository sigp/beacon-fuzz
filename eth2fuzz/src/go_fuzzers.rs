use failure::{Error, ResultExt};
use std::env;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

use crate::env::{corpora_dir, state_dir, workspace_dir};
use crate::fuzzers::{write_fuzzer_target, FuzzerConfig, FuzzerQuit};
use crate::targets::{prepare_targets_workspace, Targets};
use crate::utils::copy_dir;

/***********************************************
name: libfuzzer for Go using go-fuzz-build
github: XXX
***********************************************/

pub struct FuzzerGoLibfuzzer {
    /// Fuzzer name.
    pub name: String,
    /// Source code / template dir
    pub dir: PathBuf,
    /// Workspace dir
    pub work_dir: PathBuf,
    /// Internal workspace dir
    pub workspace_dir: PathBuf,
    /// fuzzing config
    pub config: FuzzerConfig,
}

impl FuzzerGoLibfuzzer {
    /// Check if libfuzzer is installed
    fn is_available() -> Result<(), Error> {
        let fuzzer_output = Command::new("bin/go114-fuzz-build")
            //.env("GOPATH", workspace_dir()?.join("gofuzz"))
            .arg("-h")
            .output()?;
        if fuzzer_output.status.code() != Some(2) {
            bail!("go114-fuzz-build not available, install with `go get -u github.com/mdempsky/go114-fuzz-build`");
            //bail!("go-fuzz-build not available, install with `go get github.com/dvyukov/go-fuzz/go-fuzz-build`");
        }
        //let fuzzer_output = Command::new("go-fuzz").output()?;
        //if fuzzer_output.status.code() != Some(2) {
        //    bail!(
        //        "go-fuzz not available, install with `go get github.com/dvyukov/go-fuzz/go-fuzz`"
        //    );
        //}
        Ok(())
    }

    /// Create a new FuzzerGoLibfuzzer
    pub fn new(config: FuzzerConfig) -> Result<FuzzerGoLibfuzzer, Error> {
        // Test if fuzzer engine installed
        FuzzerGoLibfuzzer::is_available()?;
        let cwd = env::current_dir().context("error getting current directory")?;
        let fuzzer = FuzzerGoLibfuzzer {
            name: "gofuzz".to_string(),
            dir: cwd.join("fuzzers").join("gofuzz"),
            work_dir: cwd.join("workspace").join("gofuzz"),
            workspace_dir: cwd
                .join("workspace")
                .join("gofuzz")
                .join("gofuzz_workspace"),
            config,
        };
        Ok(fuzzer)
    }

    fn prepare_fuzzer_workspace(&self) -> Result<(), Error> {
        let from = &self.dir;
        let workspace = &self.work_dir;
        copy_dir(from.to_path_buf(), workspace.to_path_buf())?;
        Ok(())
    }

    fn some_kind_of_uppercase_first_letter(&self, s: &str) -> String {
        let mut c = s.chars();
        match c.next() {
            None => String::new(),
            Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
        }
    }

    #[allow(unreachable_code)]
    /// Run the fuzzer for the given target
    pub fn run(&self, target: Targets) -> Result<(), Error> {
        // check if target is supported by this fuzzer
        // TODO - change to make it automatic
        if target.language() != "go" {
            bail!(format!("{} incompatible for this target", self.name));
        }

        // get corpora dir of the target
        let corpora_dir = corpora_dir()?.join(target.corpora());
        // copy targets source files
        //prepare_targets_workspace()?;
        // create fuzzer folder inside workspace/
        //self.prepare_fuzzer_workspace()?;

        //panic!("FuzzerGoLibfuzzer not implemented yet");

        // write all fuzz targets inside workspace folder
        //write_fuzzer_target(&self.dir, &self.work_dir, target)?;
        println!("[eth2fuzz] {}: {} created", self.name, target.name());

        //cd /eth2fuzz/src/github.com/prysmaticlabs/prysm/
        // cp /eth2fuzz/workspace/gofuzz/lib.go .

        fs::copy(
            "/eth2fuzz/workspace/gofuzz/lib.go",
            "/eth2fuzz/src/github.com/prysmaticlabs/prysm/lib.go",
        )?;

        //eth2fuzz/bin/go114-fuzz-build -func FuzzBlockHeader github.com/prysmaticlabs/prysm

        let compile_bin = Command::new("/eth2fuzz/bin/go114-fuzz-build")
            .args(&[
                "-func",
                &self.some_kind_of_uppercase_first_letter(&target.name()),
                "github.com/prysmaticlabs/prysm",
            ])
            //.arg(&format!("{}.{}", target.name(), target.language()))
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

        // TODO - needed?
        if !compile_bin.success() {
            return Err(FuzzerQuit.into());
        }

        //cp prysm-fuzz.a /eth2fuzz/workspace/gofuzz/

        fs::copy(
            "/eth2fuzz/src/github.com/prysmaticlabs/prysm/prysm-fuzz.a",
            "/eth2fuzz/workspace/gofuzz/prysm-fuzz.a",
        )?;

        //cd /eth2fuzz/workspace/gofuzz/

        //clang -fsanitize=fuzzer prysm-fuzz.a /eth2fuzz/pkg/mod/github.com/herumi/bls-eth-go-binary\@v0.0.0-20200522010937-01d282b5380b/bls/lib/linux/amd64/libbls384_256.a  -o prysm_FuzzBlockHeader.libfuzzer

        let compile_bin2 = Command::new("clang")
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

        // TODO - needed?
        if !compile_bin2.success() {
            return Err(FuzzerQuit.into());
        }

        //ETH2FUZZ_BEACONSTATE=/eth2fuzz/workspace/corpora/beaconstate ./prysm_FuzzBlockHeader.libfuzzer /eth2fuzz/workspace/corpora/block_header/

        let _corpus_dir = &self.workspace_dir;

        // create fuzzing config arguments
        // handle timeout option
        let mut args: Vec<String> = Vec::new();
        if let Some(timeout) = self.config.timeout {
            args.push(format!("-max_total_time={}", timeout));
        };
        // handle threading option
        if let Some(thread) = self.config.thread {
            args.push(format!("-workers={}", thread));
            args.push(format!("-jobs={}", thread));
        };
        // handle seed option
        if let Some(seed) = self.config.seed {
            args.push(format!("-seed={}", seed));
        };
        args.push(format!("{}", &corpora_dir.display()));

        // Run the fuzzer
        let fuzzer_bin = Command::new(&format!("./{}.libfuzzer", target.name()))
            .env(
                "ETH2FUZZ_BEACONSTATE",
                format!("{}", state_dir()?.display()),
            )
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

        // TODO - needed?
        if !fuzzer_bin.success() {
            return Err(FuzzerQuit.into());
        }
        Ok(())
    }
}
