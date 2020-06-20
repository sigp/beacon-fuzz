use failure::{Error, ResultExt};
use std::env;
use std::ffi::OsStr;
use std::fs;
use std::path::PathBuf;
use std::process::Command;
use strum::IntoEnumIterator;

use crate::env::{corpora_dir, state_dir};
use crate::fuzzers::{write_fuzzer_target, FuzzerConfig, FuzzerQuit};
use crate::targets::{prepare_targets_workspace, Targets};
use crate::utils::copy_dir;

static LANGUAGE: &str = "rust";

/***********************************************
name: honggfuzz-rs
github: https://github.com/rust-fuzz/honggfuzz-rs
***********************************************/

pub struct FuzzerHfuzz {
    /// Fuzzer name.
    pub name: String,
    /// Source code / template dir
    pub dir: PathBuf,
    /// Workspace dir
    pub work_dir: PathBuf,
    /// fuzzing config
    pub config: FuzzerConfig,
}

impl FuzzerHfuzz {
    /// Check if `cargo hfuzz` is installed
    pub fn is_available() -> Result<(), Error> {
        println!("[eth2fuzz] Testing FuzzerHfuzz is available");
        let fuzzer_output = Command::new("cargo").arg("hfuzz").arg("version").output()?;
        if !fuzzer_output.status.success() {
            bail!("hfuzz not available, install with `cargo install --force honggfuzz`");
        }
        Ok(())
    }

    /// Create a new FuzzerHfuzz
    pub fn new(config: FuzzerConfig) -> Result<FuzzerHfuzz, Error> {
        // Test if fuzzer engine installed
        FuzzerHfuzz::is_available()?;

        let cwd = env::current_dir().context("error getting current directory")?;
        let fuzzer = FuzzerHfuzz {
            name: "Honggfuzz".to_string(),
            dir: cwd.join("fuzzers").join("rust-honggfuzz"),
            work_dir: cwd.join("workspace").join("hfuzz"),
            config,
        };
        Ok(fuzzer)
    }

    // TODO - simplify this function
    fn prepare_fuzzer_workspace(&self) -> Result<(), Error> {
        let hfuzz_dir = &self.work_dir;
        fs::create_dir_all(&hfuzz_dir)
            .context(format!("unable to create {} dir", hfuzz_dir.display()))?;

        let src_dir = hfuzz_dir.join("src");
        fs::create_dir_all(&src_dir)
            .context(format!("unable to create {} dir", src_dir.display()))?;

        fs::copy(self.dir.join("Cargo.toml"), hfuzz_dir.join("Cargo.toml"))?;
        fs::copy(self.dir.join("template.rs"), hfuzz_dir.join("template.rs"))?;
        fs::copy(
            self.dir.join("simple_template.rs"),
            hfuzz_dir.join("simple_template.rs"),
        )?;
        fs::copy(self.dir.join("src").join("lib.rs"), src_dir.join("lib.rs"))?;
        Ok(())
    }

    pub fn run(&self, target: Targets) -> Result<(), Error> {
        // check if target is supported by this fuzzer
        if target.language() != LANGUAGE {
            bail!(format!("{} incompatible for this target", self.name));
        }

        // get path to corpora
        let corpora_dir = corpora_dir()?.join(target.corpora());

        // copy targets folder into workspace
        prepare_targets_workspace()?;

        // create hfuzz folder inside workspace/
        self.prepare_fuzzer_workspace()?;

        // write all fuzz targets inside hfuzz folder
        write_fuzzer_target(&self.dir, &self.work_dir, target)?;
        println!("[eth2fuzz] {}: {} created", self.name, target.name());

        // sanitizers
        let rust_args = format!(
            "{} \
            {}",
            if let Some(san) = self.config.sanitizer {
                format!("-Z sanitizer={}", san.name())
            } else {
                "".into()
            },
            env::var("RUSTFLAGS").unwrap_or_default()
        );

        // Handle seed option
        if self.config.seed != None {
            println!("[eth2fuzz] {}: seed not supported", self.name);
        }

        // prepare arguments
        let hfuzz_args = format!(
            "{} \
             {} \
             {} \
             {}",
            if let Some(t) = self.config.timeout {
                format!("--run_time {}", t)
            } else {
                "".into()
            },
            "-t 60",
            // Set number of thread
            if let Some(n) = self.config.thread {
                format!("--threads {}", n)
            } else {
                "".into()
            },
            env::var("HFUZZ_RUN_ARGS").unwrap_or_default()
        );

        // Honggfuzz will first build than run the fuzzer using cargo
        let fuzzer_bin = Command::new("cargo")
            .args(&["+nightly", "hfuzz", "run", &target.name()])
            .env("RUSTFLAGS", &rust_args)
            .env("HFUZZ_RUN_ARGS", &hfuzz_args)
            //.env("HFUZZ_BUILD_ARGS", "opt-level=3")
            .env("HFUZZ_INPUT", corpora_dir)
            .env(
                "ETH2FUZZ_BEACONSTATE",
                format!("{}", state_dir()?.display()),
            )
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

        if !fuzzer_bin.success() {
            return Err(FuzzerQuit.into());
        }
        Ok(())
    }
}

/***********************************************
name: afl-rs
github: https://github.com/rust-fuzz/afl.rs
***********************************************/

pub struct FuzzerAfl {
    /// Fuzzer name.
    pub name: String,
    /// Source code / template dir
    pub dir: PathBuf,
    /// Workspace dir
    pub work_dir: PathBuf,
    /// fuzzing config
    pub config: FuzzerConfig,
}

impl FuzzerAfl {
    /// Check if `cargo afl` is installed
    pub fn is_available() -> Result<(), Error> {
        println!("[eth2fuzz] Testing FuzzerAfl is available");
        let fuzzer_output = Command::new("cargo").arg("afl").arg("--version").output()?;
        if !fuzzer_output.status.success() {
            bail!("afl-rs not available, install with `cargo install --force afl`");
        }
        Ok(())
    }

    /// Create a new FuzzerAfl
    pub fn new(config: FuzzerConfig) -> Result<FuzzerAfl, Error> {
        // Test if fuzzer engine installed
        FuzzerAfl::is_available()?;

        let cwd = env::current_dir().context("error getting current directory")?;
        let fuzzer = FuzzerAfl {
            name: "Afl++".to_string(),
            dir: cwd.join("fuzzers").join("rust-afl"),
            work_dir: cwd.join("workspace").join("afl"),
            config,
        };
        Ok(fuzzer)
    }

    // TODO - simplify that
    fn prepare_fuzzer_workspace(&self) -> Result<(), Error> {
        let hfuzz_dir = &self.work_dir;
        fs::create_dir_all(&hfuzz_dir)
            .context(format!("unable to create {} dir", hfuzz_dir.display()))?;

        let src_dir = hfuzz_dir.join("src");
        fs::create_dir_all(&src_dir)
            .context(format!("unable to create {} dir", src_dir.display()))?;

        fs::copy(self.dir.join("Cargo.toml"), hfuzz_dir.join("Cargo.toml"))?;
        fs::copy(self.dir.join("template.rs"), hfuzz_dir.join("template.rs"))?;
        fs::copy(
            self.dir.join("simple_template.rs"),
            hfuzz_dir.join("simple_template.rs"),
        )?;
        fs::copy(self.dir.join("src").join("lib.rs"), src_dir.join("lib.rs"))?;
        Ok(())
    }

    /// Build single target with afl
    pub fn build_afl(&self, target: Targets) -> Result<(), Error> {
        prepare_targets_workspace()?;
        // create afl folder inside workspace/
        self.prepare_fuzzer_workspace()?;

        write_fuzzer_target(&self.dir, &self.work_dir, target)?;

        // sanitizers
        let rust_args = format!(
            "{} \
            {}",
            if let Some(san) = self.config.sanitizer {
                format!("-Z sanitizer={}", san.name())
            } else {
                "".into()
            },
            env::var("RUSTFLAGS").unwrap_or_default()
        );

        let build_cmd = Command::new("cargo")
            .args(&["+nightly", "afl", "build", "--bin", &target.name()]) // TODO: not sure we want to compile afl in "--release"
            .env("RUSTFLAGS", &rust_args)
            .current_dir(&self.work_dir)
            .spawn()
            .context(format!(
                "error starting build for {} of {}",
                self.name,
                target.name()
            ))?
            .wait()
            .context(format!(
                "error while waiting for build for {} of {}",
                self.name,
                target.name()
            ))?;

        if !build_cmd.success() {
            return Err(FuzzerQuit.into());
        }

        Ok(())
    }

    pub fn run(&self, target: Targets) -> Result<(), Error> {
        // check if target is supported by this fuzzer
        if target.language() != LANGUAGE {
            bail!(format!("{} incompatible for this target", self.name));
        }

        let dir = &self.work_dir;
        let corpora_dir = corpora_dir()?.join(target.corpora());

        self.build_afl(target)?;

        // TODO - modify to use same corpus than other fuzzer
        // let corpus_dir = &self.workspace_dir;
        let corpus_dir = env::current_dir()?
            .join("workspace")
            .join("afl")
            .join("afl_workspace");
        fs::create_dir_all(&corpus_dir)
            .context(format!("unable to create {} dir", corpus_dir.display()))?;

        // Determined if existing fuzzing session exist
        let queue_dir = corpus_dir.join("queue");
        let input_arg: &OsStr = if queue_dir.is_dir() && fs::read_dir(queue_dir)?.next().is_some() {
            "-".as_ref()
        } else {
            corpora_dir.as_ref()
        };

        let mut args: Vec<String> = Vec::new();
        args.push("+nightly".to_string());
        args.push("afl".to_string());
        args.push("fuzz".to_string());
        if let Some(t) = self.config.timeout {
            args.push(format!("-V {}", t));
        };
        if let Some(seed) = self.config.seed {
            args.push(format!("-s {}", seed));
        };

        // Run the fuzzer using cargo
        let fuzzer_bin = Command::new("cargo")
            .args(args)
            //.arg("-t 30000+" ) // increase timeout to let the fuzzer pick a valid beaconstate
            .arg("-m") // remove memory limit
            .arg("none")
            .arg("-i")
            .arg(&input_arg)
            .arg("-o")
            .arg(&corpus_dir)
            .args(&["--", &format!("./target/debug/{}", target.name())])
            .env(
                "ETH2FUZZ_BEACONSTATE",
                format!("{}", state_dir()?.display()),
            )
            // env variable to skip afl checking
            .env("AFL_SKIP_CPUFREQ", "1")
            .env("AFL_SKIP_CRASHES", "1")
            .env("AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES", "1")
            .current_dir(&dir)
            .spawn()
            .context(format!(
                "error starting {:?} to run {}",
                self.name,
                target.name()
            ))?
            .wait()
            .context(format!(
                "error while waiting for {:?} running {}",
                self.name,
                target.name()
            ))?;

        if !fuzzer_bin.success() {
            return Err(FuzzerQuit.into());
        }
        Ok(())
    }
}

/***********************************************
name: libfuzzer/cargo-fuzz
github: https://github.com/rust-fuzz/cargo-fuzz
***********************************************/

pub struct FuzzerLibfuzzer {
    /// Fuzzer name.
    pub name: String,
    /// Source code / template dir
    pub dir: PathBuf,
    /// Workspace dir
    pub work_dir: PathBuf,
    /// fuzzing config
    pub config: FuzzerConfig,
}

impl FuzzerLibfuzzer {
    /// Check if `cargo fuzz` is installed
    pub fn is_available() -> Result<(), Error> {
        println!("[eth2fuzz] Testing FuzzerLibfuzzer is available");
        let fuzzer_output = Command::new("cargo")
            .arg("fuzz")
            .arg("--version")
            .output()?;
        if !fuzzer_output.status.success() {
            bail!("cargo-fuzz not available, install with `cargo install --force cargo-fuzz`");
        }
        Ok(())
    }

    /// Create a new FuzzerLibfuzzer
    pub fn new(config: FuzzerConfig) -> Result<FuzzerLibfuzzer, Error> {
        // Test if fuzzer engine installed
        FuzzerLibfuzzer::is_available()?;

        let cwd = env::current_dir().context("error getting current directory")?;
        let fuzzer = FuzzerLibfuzzer {
            name: "Libfuzzer".to_string(),
            dir: cwd.join("fuzzers").join("rust-libfuzzer"),
            work_dir: cwd.join("workspace").join("libfuzzer"),
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

    pub fn run(&self, target: Targets) -> Result<(), Error> {
        // check if target is supported by this fuzzer
        if target.language() != LANGUAGE {
            bail!(format!("{} incompatible for this target", self.name));
        }

        prepare_targets_workspace()?;
        // create afl folder inside workspace/
        self.prepare_fuzzer_workspace()?;

        let fuzz_dir = self.work_dir.join("fuzz");
        fs::create_dir_all(&fuzz_dir)
            .context(format!("unable to create {} dir", fuzz_dir.display()))?;

        let target_dir = fuzz_dir.join("fuzz_targets");

        let _ = fs::remove_dir_all(&target_dir)
            .context(format!("error removing {}", target_dir.display()));
        fs::create_dir_all(&target_dir)
            .context(format!("unable to create {} dir", target_dir.display()))?;

        fs::create_dir_all(&fuzz_dir)
            .context(format!("unable to create {} dir", fuzz_dir.display()))?;
        //println!("{:?}", fuzz_dir);

        fs::copy(
            self.dir.join("fuzz").join("Cargo.toml"),
            fuzz_dir.join("Cargo.toml"),
        )?;

        // Add all targets to libfuzzer
        for target in Targets::iter().filter(|x| x.language() == "rust") {
            write_libfuzzer_target(&self.work_dir, target)?;
        }

        let fuzz_dir = self.work_dir.join("fuzz");
        let corpus_dir = corpora_dir()?.join(target.corpora());

        // sanitizers
        let rust_args = format!(
            "{} \
            {}",
            if let Some(san) = self.config.sanitizer {
                format!("-Z sanitizer={}", san.name())
            } else {
                "".into()
            },
            env::var("RUSTFLAGS").unwrap_or_default()
        );

        // create arguments
        // corpora dir
        // max_time if provided (i.e. continuously fuzzing)
        let mut args: Vec<String> = Vec::new();
        args.push(format!("{}", &corpus_dir.display()));
        if let Some(timeout) = self.config.timeout {
            args.push("--".to_string());
            args.push(format!("-max_total_time={}", timeout));
        };
        // threading
        if let Some(thread) = self.config.thread {
            args.push(format!("-workers={}", thread));
            args.push(format!("-jobs={}", thread));
        };
        // handle seed option
        if let Some(seed) = self.config.seed {
            args.push(format!("-seed={}", seed));
        };
        // Launch the fuzzer using cargo
        let fuzzer_bin = Command::new("cargo")
            .args(&["+nightly", "fuzz", "run", &target.name()])
            .args(&args)
            .env(
                "ETH2FUZZ_BEACONSTATE",
                format!("{}", state_dir()?.display()),
            )
            .env("RUSTFLAGS", &rust_args)
            .current_dir(&fuzz_dir)
            .spawn()
            .context(format!(
                "error starting {:?} to run {}",
                self.name,
                target.name()
            ))?
            .wait()
            .context(format!(
                "error while waiting for {:?} running {}",
                self.name,
                target.name()
            ))?;

        if !fuzzer_bin.success() {
            return Err(FuzzerQuit.into());
        }
        Ok(())
    }
}

/// Add new target for libfuzzer using `cargo fuzz add`
fn write_libfuzzer_target(fuzzer_dir: &PathBuf, target: Targets) -> Result<(), Error> {
    use std::io::Write;

    let fuzz_dir = fuzzer_dir.join("fuzz");
    let template_path = fuzzer_dir.join(target.template());

    let template = fs::read_to_string(&template_path).context(format!(
        "error reading template file {}",
        template_path.display()
    ))?;

    // use `cargo fuzz add` to add new bin inside Cargo.toml
    // and create fuzz_targets dir
    // and create target.rs
    let _ = Command::new("cargo")
        .args(&["+nightly", "fuzz", "add", &target.name()])
        .current_dir(&fuzzer_dir)
        .spawn()
        .context(format!("error adding {}", target.name()))?
        .wait()
        .context(format!("error while adding {}", target.name()));

    let target_dir = fuzz_dir.join("fuzz_targets");

    let path = target_dir.join(&format!("{}.rs", target.name()));

    let mut file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&path)
        .context(format!(
            "write_libfuzzer_target error writing fuzz target binary {}",
            path.display()
        ))?;

    let source = template.replace("###TARGET###", &target.name());
    file.write_all(source.as_bytes())?;
    Ok(())
}
