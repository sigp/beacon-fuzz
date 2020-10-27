use failure::{Error, ResultExt};
use std::env;
use std::path::PathBuf;
use std::process::Command;

use crate::env::{corpora_dir, root_dir, state_dir};
use crate::fuzzers::{FuzzerConfig, FuzzerQuit};
use crate::targets::Targets;

static LANGUAGE: &str = "nim";

/***********************************************
name: libfuzzer for Nim
github: https://github.com/status-im/nim-testutils/tree/master/testutils/fuzzing#manually-with-libfuzzer
***********************************************/

pub struct FuzzerNimLibfuzzer {
    /// Fuzzer name.
    pub name: String,
    /// Source code / template dir
    pub dir: PathBuf,
    /// Workspace dir
    pub work_dir: PathBuf,
    /// fuzzing config
    pub config: FuzzerConfig,
}

impl FuzzerNimLibfuzzer {
    /// Check if libfuzzer is installed
    fn is_available() -> Result<(), Error> {
        println!("[eth2fuzz] Testing FuzzerNimLibfuzzer is available");
        let fuzzer_output = Command::new("clang").arg("--version").output()?;

        if !fuzzer_output.status.success() {
            bail!("clang not available, install with `apt install clang`");
        }
        Ok(())
    }

    /// Create a new FuzzerNimLibfuzzer
    pub fn new(config: FuzzerConfig) -> Result<FuzzerNimLibfuzzer, Error> {
        // Test if fuzzer engine installed
        FuzzerNimLibfuzzer::is_available()?;
        let cwd = env::current_dir().context("error getting current directory")?;
        let fuzzer = FuzzerNimLibfuzzer {
            name: "libfuzzer".to_string(),
            dir: cwd.join("fuzzers").join("nimlibfuzzer"),
            work_dir: cwd.join("workspace").join("nimlibfuzzer"),
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
        let corpora_dir = corpora_dir()?.join(target.corpora());

        println!(
            "[eth2fuzz] Starting fuzzing of {} with {}",
            target.name(),
            self.name
        );

        // Prepare compilation arguments
        let mut args: Vec<String> = Vec::new();
        args.push("nim".to_string()); // nim compiler
        args.push("c".to_string()); // compile arg
        args.push("-d:libFuzzer".to_string()); // libfuzzer flag
        args.push("-d:release".to_string()); // release flag
        args.push("--hints:off".to_string());
        args.push("--warnings:off".to_string());
        args.push("--verbosity:0".to_string());
        args.push("-d:chronicles_log_level=fatal".to_string());
        args.push("--noMain".to_string());
        args.push("--cc=clang".to_string());
        args.push("-d:const_preset=mainnet".to_string()); // mainnet config

        // handle fuzzer config - sanitizer
        if let Some(san) = self.config.sanitizer {
            args.push(format!("--passC=\"-fsanitize=fuzzer,{}\"", san.name()));
            args.push(format!("--passL=\"-fsanitize=fuzzer,{}\"", san.name()));
        } else {
            args.push("--passC=\"-fsanitize=fuzzer\"".to_string());
            args.push("--passL=\"-fsanitize=fuzzer\"".to_string());
        }

        // build the target
        let envsh = root_dir()?
            .parent()
            .unwrap()
            .join("nimbus-eth2")
            .join("env.sh");
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

        // Check compilation success
        if !compile_bin.success() {
            return Err(FuzzerQuit.into());
        }

        // create fuzzing config arguments
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
        let fuzzer_bin = Command::new(&format!("./{}", target.name()))
            .env(
                "ETH2FUZZ_BEACONSTATE",
                format!("{}", state_dir()?.display()),
            )
            .args(&args)
            .current_dir(&self.work_dir)
            .spawn()
            .context(format!(
                "error starting fuzzer {} to run {}",
                self.name,
                target.name()
            ))?
            .wait()
            .context(format!(
                "error while waiting for fuzzer {} running {}",
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

/***********************************************
name: afl for Nim
github: https://github.com/status-im/nim-testutils/tree/master/testutils/fuzzing#manually-with-afl
***********************************************/

/*
pub struct FuzzerNimAfl {
    /// Fuzzer name.
    pub name: String,
    /// Source code / template dir
    pub dir: PathBuf,
    /// Workspace dir
    pub work_dir: PathBuf,
    /// fuzzing config
    pub config: FuzzerConfig,
}

impl FuzzerNimAfl {
    /// Check if afl is installed
    fn is_available() -> Result<(), Error> {
        let fuzzer_output = Command::new("afl-fuzz").output()?;

        if fuzzer_output.status.code() != Some(1) {
            bail!("afl-fuzz not available, install with `apt install afl++`");
        }
        Ok(())
    }

    /// Create a new FuzzerNimAfl
    pub fn new(config: FuzzerConfig) -> Result<FuzzerNimAfl, Error> {
        // Test if fuzzer engine installed
        FuzzerNimAfl::is_available()?;
        let cwd = env::current_dir().context("error getting current directory")?;
        let fuzzer = FuzzerNimAfl {
            name: "afl".to_string(),
            dir: cwd.join("fuzzers").join("nimafl"),
            work_dir: cwd.join("workspace").join("nimafl"),
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

    /// Run the fuzzer for the given target
    pub fn run(&self, target: Targets) -> Result<(), Error> {
        // check if target is supported by this fuzzer
        if target.language() != LANGUAGE {
            bail!(format!("{} incompatible for this target", self.name));
        }

        // get corpora dir of the target
        let corpora_dir = corpora_dir()?.join(target.corpora());
        // copy targets source files
        // prepare_targets_workspace()?;
        // create fuzzer folder inside workspace/
        // self.prepare_fuzzer_workspace()?;

        // write all fuzz targets inside workspace folder
        write_fuzzer_target(&self.dir, &self.work_dir, target)?;
        println!("[eth2fuzz] {}: {} created", self.name, target.name());

        let mut args: Vec<String> = Vec::new();
        args.push("nim".to_string()); // nim compiler
        args.push("c".to_string()); // compile arg
        args.push("-d:afl".to_string()); // afl flag
        args.push("-d:release".to_string()); // release flag
        args.push("-d:chronicles_log_level=fatal".to_string());
        args.push("-d:noSignalHandler".to_string());
        args.push("--hints:off".to_string());
        args.push("--warnings:off".to_string());
        args.push("--verbosity:0".to_string());
        args.push("-d:clangfast".to_string());
        args.push("--cc=clang".to_string());
        args.push("--clang.exe=afl-clang-fast".to_string());
        args.push("--clang.linkerexe=afl-clang-fast".to_string());
        args.push("-d:const_preset=mainnet".to_string()); // mainnet config

        // handle fuzzer config - sanitizer
        if let Some(san) = self.config.sanitizer {
            args.push(format!("--passC=\"-fsanitize={}\"", san.name()));
            args.push(format!("--passL=\"-fsanitize={}\"", san.name()));
        }

        // build the target
        let envsh = workspace_dir()?.join("nimbus-eth2").join("env.sh");
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

        //let corpus_dir = &self.workspace_dir;
        let corpus_dir = env::current_dir()?.join("workspace")
                .join("nimafl")
                .join("nimafl_workspace"),

        if self.config.timeout != None {
            println!("[eth2fuzz] {}: timeout not supported", self.name);
        }
        if self.config.thread != None {
            println!("[eth2fuzz] {}: thread not supported", self.name);
        }

        // Run the fuzzer
        let fuzzer_bin = Command::new("afl-fuzz")
            .env(
                "ETH2FUZZ_BEACONSTATE",
                format!("{}", state_dir()?.display()),
            )
            .arg("-m") // remove memory limit
            .arg("none") // remove memory limit
            .arg("-i")
            .arg(&corpora_dir)
            .arg("-o")
            .arg(&corpus_dir)
            .args(&["--", &format!("./{}", target.name())])
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
*/
