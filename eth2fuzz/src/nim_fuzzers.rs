use failure::{Error, ResultExt};
use std::env;
use std::path::PathBuf;
use std::process::Command;

use crate::env::{corpora_dir, state_dir, workspace_dir};
use crate::fuzzers::{write_fuzzer_target, FuzzerQuit};
use crate::targets::{prepare_targets_workspace, Targets};
use crate::utils::copy_dir;

/***********************************************
name: afl for Nim
github: https://github.com/status-im/nim-testutils/tree/master/testutils/fuzzing#manually-with-afl
***********************************************/

pub struct FuzzerNimAfl {
    /// Fuzzer name.
    pub name: String,
    /// Source code / template dir
    pub dir: PathBuf,
    /// Workspace dir
    pub work_dir: PathBuf,
    /// Internal workspace dir
    pub workspace_dir: PathBuf,
    /// timeout
    pub timeout: Option<i32>,
    /// thread
    pub thread: Option<i32>,
}

impl FuzzerNimAfl {
    /// Check if afl is installed
    fn is_available() -> Result<(), Error> {
        let fuzzer_output = Command::new("afl-fuzz").output()?;

        if fuzzer_output.status.code() != Some(1) {
            bail!("afl-fuzz not available, install with `apt install afl`");
        }
        Ok(())
    }

    /// Create a new FuzzerNimAfl
    pub fn new(timeout: Option<i32>, thread: Option<i32>) -> Result<FuzzerNimAfl, Error> {
        // Test if fuzzer engine installed
        FuzzerNimAfl::is_available()?;
        let cwd = env::current_dir().context("error getting current directory")?;
        let fuzzer = FuzzerNimAfl {
            name: "afl".to_string(),
            dir: cwd.join("fuzzers").join("nimafl"),
            work_dir: cwd.join("workspace").join("nimafl"),
            workspace_dir: cwd
                .join("workspace")
                .join("nimafl")
                .join("nimafl_workspace"),
            timeout: timeout,
            thread: thread,
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
        // TODO - change to make it automatic
        if target.language() != "nim" {
            bail!(format!("{} incompatible for this target", self.name));
        }

        // get corpora dir of the target
        let corpora_dir = corpora_dir()?.join(target.corpora());
        // copy targets source files
        prepare_targets_workspace()?;
        // create fuzzer folder inside workspace/
        self.prepare_fuzzer_workspace()?;

        // write all fuzz targets inside workspace folder
        write_fuzzer_target(&self.dir, &self.work_dir, target)?;
        println!("[eth2fuzz] {}: {} created", self.name, target.name());

        // build the target
        let envsh = workspace_dir()?.join("nim-beacon-chain").join("env.sh");
        let compile_bin = Command::new(envsh)
            .arg("nim") // nim compiler
            .arg("c") // compile arg
            .arg("-d:afl")
            .arg("-d:release")
            .arg("-d:chronicles_log_level=fatal")
            .arg("-d:noSignalHandler")
            .arg("--cc=clang")
            .arg("--clang.exe=afl-clang-fast")
            .arg("--clang.linkerexe=afl-clang-fast")
            .arg("-d:clangfast")
            .arg("-d:const_preset=mainnet") // mainnet config
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
            Err(FuzzerQuit)?;
        }

        let corpus_dir = &self.workspace_dir;

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
            Err(FuzzerQuit)?;
        }
        Ok(())
    }
}

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
    /// Internal workspace dir
    pub workspace_dir: PathBuf,
    /// timeout
    pub timeout: Option<i32>,
    /// thread
    pub thread: Option<i32>,
}

impl FuzzerNimLibfuzzer {
    /// Check if libfuzzer is installed
    fn is_available() -> Result<(), Error> {
        let fuzzer_output = Command::new("clang").arg("--version").output()?;

        if !fuzzer_output.status.success() {
            bail!("clang not available, install with `apt install clang`");
        }
        Ok(())
    }

    /// Create a new FuzzerNimLibfuzzer
    pub fn new(timeout: Option<i32>, thread: Option<i32>) -> Result<FuzzerNimLibfuzzer, Error> {
        // Test if fuzzer engine installed
        FuzzerNimLibfuzzer::is_available()?;
        let cwd = env::current_dir().context("error getting current directory")?;
        let fuzzer = FuzzerNimLibfuzzer {
            name: "libfuzzer".to_string(),
            dir: cwd.join("fuzzers").join("nimlibfuzzer"),
            work_dir: cwd.join("workspace").join("nimlibfuzzer"),
            workspace_dir: cwd
                .join("workspace")
                .join("nimlibfuzzer")
                .join("nimlibfuzzer_workspace"),
            timeout: timeout,
            thread: thread,
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
        // TODO - change to make it automatic
        if target.language() != "nim" {
            bail!(format!("{} incompatible for this target", self.name));
        }

        // get corpora dir of the target
        let corpora_dir = corpora_dir()?.join(target.corpora());
        // copy targets source files
        prepare_targets_workspace()?;
        // create fuzzer folder inside workspace/
        self.prepare_fuzzer_workspace()?;

        // write all fuzz targets inside workspace folder
        write_fuzzer_target(&self.dir, &self.work_dir, target)?;
        println!("[eth2fuzz] {}: {} created", self.name, target.name());

        // build the target
        let envsh = workspace_dir()?.join("nim-beacon-chain").join("env.sh");
        let compile_bin = Command::new(envsh)
            .arg("nim") // nim compiler
            .arg("c") // compile arg
            .arg("-d:libFuzzer")
            .arg("-d:release")
            .arg("-d:chronicles_log_level=fatal")
            .arg("--noMain")
            .arg("--cc=clang")
            .arg("--passC=\"-fsanitize=fuzzer\"")
            .arg("--passL=\"-fsanitize=fuzzer\"")
            // mainnet config
            .arg("-d:const_preset=mainnet")
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
            Err(FuzzerQuit)?;
        }

        let corpus_dir = &self.workspace_dir;

        // create arguments
        // corpora dir
        // max_time if provided (i.e. continuously fuzzing)
        let mut args: Vec<String> = Vec::new();
        args.push(format!("{}", &corpora_dir.display()));
        if let Some(timeout) = self.timeout {
            args.push(format!("-max_total_time={}", timeout));
        };

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
            Err(FuzzerQuit)?;
        }
        Ok(())
    }
}
