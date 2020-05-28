use failure::{Error, ResultExt};
use std::env;
use std::path::PathBuf;
use std::process::Command;

use crate::env::{corpora_dir, workspace_dir};
use crate::fuzzers::{write_fuzzer_target, FuzzerQuit};
use crate::targets::{prepare_targets_workspace, Targets};
use crate::utils::copy_dir;

/***********************************************
name: afl
github: https://github.com/google/afl
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
    /// Check if jsfuzz is installed
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

    /// Check if jsfuzz is installed
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
        // ../../env.sh nim c -d:afl -d:release -d:chronicles_log_level=fatal
        // -d:noSignalHandler --cc=gcc --gcc.exe=afl-gcc --gcc.linkerexe=afl-gcc
        //-d:const_preset=mainnet attester_slashing.nim

        let envsh = workspace_dir()?.join("nim-beacon-chain").join("env.sh");
        let compile_bin = Command::new(envsh)
            .arg("nim") // nim compiler
            .arg("c") // compile arg
            .arg("-d:afl")
            .arg("-d:release")
            .arg("-d:chronicles_log_level=fatal")
            .arg("-d:noSignalHandler")
            //.arg("--cc=gcc")
            .arg("--gcc.exe=afl-gcc")
            .arg("--gcc.linkerexe=afl-gcc")
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
