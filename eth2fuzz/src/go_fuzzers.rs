use failure::{Error, ResultExt};
use std::env;
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
        let fuzzer_output = Command::new("go-fuzz-build").output()?;
        if fuzzer_output.status.code() != Some(2) {
            bail!("go-fuzz-build not available, install with `go get github.com/dvyukov/go-fuzz/go-fuzz-build`");
        }
        let fuzzer_output = Command::new("go-fuzz").output()?;
        if fuzzer_output.status.code() != Some(2) {
            bail!(
                "go-fuzz not available, install with `go get github.com/dvyukov/go-fuzz/go-fuzz`"
            );
        }
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

    #[allow(unreachable_code)]
    /// Run the fuzzer for the given target
    pub fn run(&self, target: Targets) -> Result<(), Error> {
        // check if target is supported by this fuzzer
        // TODO - change to make it automatic
        if target.language() != "go" {
            bail!(format!("{} incompatible for this target", self.name));
        }

        panic!("FuzzerGoLibfuzzer not implemented yet");

        // get corpora dir of the target
        let corpora_dir = corpora_dir()?.join(target.corpora());
        // copy targets source files
        prepare_targets_workspace()?;
        // create fuzzer folder inside workspace/
        self.prepare_fuzzer_workspace()?;

        // write all fuzz targets inside workspace folder
        write_fuzzer_target(&self.dir, &self.work_dir, target)?;
        println!("[eth2fuzz] {}: {} created", self.name, target.name());

        let mut args: Vec<String> = Vec::new();
        args.push("TODO".to_string());
        // args.push("nim".to_string()); // nim compiler
        // args.push("c".to_string()); // compile arg
        // args.push("-d:libFuzzer".to_string()); // libfuzzer flag
        // args.push("-d:release".to_string()); // release flag
        // args.push("--hints:off".to_string());
        // args.push("--warnings:off".to_string());
        // args.push("--verbosity:0".to_string());
        // args.push("-d:chronicles_log_level=fatal".to_string());
        // args.push("--noMain".to_string());
        // args.push("--cc=clang".to_string());
        // args.push("-d:const_preset=mainnet".to_string()); // mainnet config

        // handle fuzzer config - sanitizer
        if let Some(san) = self.config.sanitizer {
            args.push(format!("--passC=\"-fsanitize=fuzzer,{}\"", san.name()));
            args.push(format!("--passL=\"-fsanitize=fuzzer,{}\"", san.name()));
        } else {
            args.push("--passC=\"-fsanitize=fuzzer\"".to_string());
            args.push("--passL=\"-fsanitize=fuzzer\"".to_string());
        }

        // build the target
        let envsh = workspace_dir()?.join("nim-beacon-chain").join("env.sh");
        let compile_bin = Command::new(envsh)
            .args(args)
            .arg(&format!("{}.{}", target.name(), target.language()))
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
        if !compile_bin.success() {
            return Err(FuzzerQuit.into());
        }

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
        let fuzzer_bin = Command::new(&format!("./{}", target.name()))
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
