use failure::{Error, ResultExt};
use std::env;
use std::path::PathBuf;
use std::process::Command;

use crate::env::corpora_dir;
use crate::fuzzers::{write_fuzzer_target, FuzzerQuit};
use crate::targets::{prepare_targets_workspace, Targets};
use crate::utils::copy_dir;

/***********************************************
name: jsfuzz
github: https://github.com/fuzzitdev/jsfuzz
***********************************************/

pub struct FuzzerJsFuzz {
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

impl FuzzerJsFuzz {
    /// Check if jsfuzz is installed
    fn is_available() -> Result<(), Error> {
        let fuzzer_output = Command::new("jsfuzz").arg("--version").output()?;

        if !fuzzer_output.status.success() {
            bail!("jsfuzz not available, install with `npm i -g jsfuzz`");
        }
        Ok(())
    }

    /// Create a new FuzzerJsFuzz
    pub fn new(timeout: Option<i32>, thread: Option<i32>) -> Result<FuzzerJsFuzz, Error> {
        // Test if fuzzer engine installed
        FuzzerJsFuzz::is_available()?;
        let cwd = env::current_dir().context("error getting current directory")?;
        let fuzzer = FuzzerJsFuzz {
            name: "JsFuzz".to_string(),
            dir: cwd.join("fuzzers").join("js-jsfuzz"),
            work_dir: cwd.join("workspace").join("jsfuzz"),
            workspace_dir: cwd
                .join("workspace")
                .join("jsfuzz")
                .join("jsfuzz_workspace"),
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
        if target.language() != "js" {
            bail!("FuzzerJsFuzz incompatible for this target");
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

        // Run the fuzzer
        let fuzzer_bin = Command::new("jsfuzz")
            .arg(&target.name())
            .arg(corpora_dir)
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
