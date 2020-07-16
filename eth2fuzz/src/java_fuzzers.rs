use failure::{Error, ResultExt};
use std::env;

use std::path::PathBuf;
use std::process::Command;

use crate::env::{corpora_dir, state_dir};
use crate::fuzzers::{FuzzerConfig, FuzzerQuit};
use crate::targets::Targets;

/***********************************************
name: Afl with jqf for java fuzzing
github: https://github.com/rohanpadhye/jqf/wiki/Fuzzing-with-AFL
***********************************************/

static LANGUAGE: &str = "java";

pub struct FuzzerJavaJQFAfl {
    /// Fuzzer name.
    pub name: String,
    /// Source code / template dir
    pub dir: PathBuf,
    /// Workspace dir
    pub work_dir: PathBuf,
    /// fuzzing config
    pub config: FuzzerConfig,
}

impl FuzzerJavaJQFAfl {
    /// Check if all tools are installed (jqf, afl & javac)
    fn is_available() -> Result<(), Error> {
        println!("[eth2fuzz] Testing FuzzerJavaJQFAfl is available");
        let fuzzer_output = Command::new("jqf/bin/jqf-afl-fuzz").arg("-h").output()?;
        if fuzzer_output.status.code() != Some(1) {
            bail!("jqf-afl-fuzz not available");
        }
        let fuzzer_output = Command::new("afl-fuzz").arg("-h").output()?;
        if fuzzer_output.status.code() != Some(1) {
            bail!("afl-fuzz not available");
        }
        let fuzzer_output = Command::new("javac").arg("--version").output()?;
        if !fuzzer_output.status.success() {
            bail!("javac not available");
        }
        Ok(())
    }

    /// Create a new FuzzerJavaJQFAfl
    pub fn new(config: FuzzerConfig) -> Result<FuzzerJavaJQFAfl, Error> {
        // Test if fuzzer engine installed
        FuzzerJavaJQFAfl::is_available()?;
        let cwd = env::current_dir().context("error getting current directory")?;

        // Create the fuzzer
        let fuzzer = FuzzerJavaJQFAfl {
            name: "javafuzz".to_string(),
            dir: cwd.join("fuzzers").join("javafuzz"),
            work_dir: cwd.join("workspace").join("javafuzz"),
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

        let compile_lib = Command::new("./tekuclass.sh")
            .current_dir(&self.work_dir)
            .output()?;
        let java_class = compile_lib.stdout;

        // javac -cp .:$(./tekuclass.sh) TekuFuzz.java
        // Compile java lib
        let compile_lib = Command::new("javac")
            .args(&[
                "-cp",
                &format!(".:{}", String::from_utf8(java_class.clone())?),
                "TekuFuzz.java",
            ])
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

        // Check compile success
        if !compile_lib.success() {
            return Err(FuzzerQuit.into());
        }

        // ETH2FUZZ_BEACONSTATE=/eth2fuzz/workspace/corpora/beaconstate ./prysm_FuzzBlockHeader.libfuzzer /eth2fuzz/workspace/corpora/block_header/

        // handle fuzzing config arguments
        // - timeout option
        // handle fuzzing options
        let mut args: Vec<String> = Vec::new();
        let cmd = match self.config.timeout {
            None => "/eth2fuzz/jqf/bin/jqf-afl-fuzz".to_string(),
            Some(time) => {
                args.push(format!("{}", time));
                args.push("/eth2fuzz/jqf/bin/jqf-afl-fuzz".to_string());
                "timeout".to_string()
            }
        };
        if self.config.thread != None {
            println!("[eth2fuzz] {}: thread not supported", self.name);
        }
        if self.config.sanitizer != None {
            println!("[eth2fuzz] {}: sanitizer not supported", self.name);
        }

        // timeout
        args.push("-t".to_string());
        args.push("60000".to_string());

        // enable jqf logging
        args.push("-v".to_string());

        // input corpora
        args.push("-i".to_string());
        args.push(format!("{}", &corpora_dir.display()));

        // remove memory limit
        args.push("-m".to_string());
        args.push("none".to_string());

        // out corpora
        args.push("-o".to_string());
        args.push(format!("out_{}", &target.name()));

        // java classpath
        args.push("-c".to_string());
        args.push(String::from_utf8(java_class)?);

        // lib name
        args.push("TekuFuzz".to_string());

        // function targeted name
        args.push(target.name());

        // ../jqf/bin/jqf-afl-fuzz -i ../corpora/block -m none -o out_block -c $(./tekuclass.sh) TekuFuzz teku_block

        // Run the fuzzer
        let fuzzer_bin = Command::new(cmd)
            // beaconstate folder
            .env(
                "ETH2FUZZ_BEACONSTATE",
                format!("{}", state_dir()?.display()),
            )
            // env variable to skip afl checking
            .env("AFL_SKIP_CPUFREQ", "1")
            .env("AFL_AUTORESUME", "1")
            .env("AFL_SKIP_CRASHES", "1")
            .env("AFL_HANG_TMOUT", "60000")
            .env("AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES", "1")
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
