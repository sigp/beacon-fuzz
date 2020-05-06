extern crate clap;
extern crate failure;
extern crate regex;
extern crate structopt;

extern crate fs_extra;

use std::env;

use std::ffi::OsStr;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

use failure::{Error, ResultExt};
use regex::Regex;
use structopt::StructOpt;

pub fn root_dir() -> Result<PathBuf, Error> {
    let p = env::var("CARGO_MANIFEST_DIR")
        .map(From::from)
        .or_else(|_| env::current_dir())?;
    Ok(p)
}

pub fn targets_dir() -> Result<PathBuf, Error> {
    let p = root_dir()?.join("targets");
    Ok(p)
}

pub fn workspace_dir() -> Result<PathBuf, Error> {
    let p = root_dir()?.join("workspace");
    fs::create_dir_all(&p).context(format!("unable to create workspace dir"))?;
    Ok(p)
}

pub fn corpora_dir() -> Result<PathBuf, Error> {
    let p = workspace_dir()?.join("corpora");
    Ok(p)
}

pub fn state_dir() -> Result<PathBuf, Error> {
    let seed_dir = corpora_dir()?.join("beaconstate");
    fs::create_dir_all(&seed_dir).context(format!("unable to create corpora/beaconstate dir"))?;
    Ok(seed_dir)
}

pub fn get_targets() -> Result<Vec<String>, Error> {
    let source = targets_dir()?.join("src/lib.rs");
    let targets_rs = fs::read_to_string(&source).context(format!("unable to read {:?}", source))?;
    let match_fuzz_fs = Regex::new(r"pub fn fuzz_(\w+)\(")?;
    let target_names = match_fuzz_fs
        .captures_iter(&targets_rs)
        .map(|x| x[1].to_string());
    Ok(target_names.collect())
}

pub fn prepare_targets_workspace() -> Result<(), Error> {
    use fs_extra::dir::{copy, CopyOptions};
    let from = targets_dir()?;
    let workspace = workspace_dir()?;

    let mut options = CopyOptions::new();
    options.overwrite = true;
    options.skip_exist = true;
    options.copy_inside = true;
    copy(from, workspace, &options)?;
    Ok(())
}

// TODO: rework it with struct for targets and/or config
fn corpora_target(target: &str) -> Result<PathBuf, Error> {
    let path = match target {
        "lighthouse_attestation" => corpora_dir()?.join("attestation"),
        "lighthouse_attester_slashing" => corpora_dir()?.join("attester_slashing"),
        "lighthouse_block" => corpora_dir()?.join("block"),
        "lighthouse_block_header" => corpora_dir()?.join("block_header"),
        "lighthouse_deposit" => corpora_dir()?.join("deposit"),
        "lighthouse_proposer_slashing" => corpora_dir()?.join("proposer_slashing"),
        "lighthouse_voluntary_exit" => corpora_dir()?.join("voluntary_exit"),
        "lighthouse_beaconstate" => corpora_dir()?.join("beaconstate"),
        _ => panic!(format!("corpora_target unknown for {}", target)),
    };
    Ok(path)
}

arg_enum! {
    #[derive(StructOpt, Debug, Clone, Copy, PartialEq, Eq)]
    pub enum Fuzzer {
        Afl,
        Honggfuzz,
        Libfuzzer
    }
}

#[derive(Fail, Debug)]
#[fail(display = "[eth2fuzz] Fuzzer quit")]
pub struct FuzzerQuit;

pub struct FuzzerHfuzz {
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

impl FuzzerHfuzz {
    /// Create a new FuzzerHfuzz
    pub fn new(timeout: Option<i32>, thread: Option<i32>) -> Result<FuzzerHfuzz, Error> {
        let cwd = env::current_dir().context("error getting current directory")?;
        let fuzzer = FuzzerHfuzz {
            name: "Honggfuzz".to_string(),
            dir: cwd.join("fuzzer-honggfuzz"),
            work_dir: cwd.join("workspace").join("hfuzz"),
            workspace_dir: cwd.join("workspace").join("hfuzz").join("hfuzz_workspace"),
            timeout: timeout,
            thread: thread,
        };
        Ok(fuzzer)
    }

    fn prepare_fuzzer_workspace(&self) -> Result<(), Error> {
        let hfuzz_dir = &self.work_dir;
        fs::create_dir_all(&hfuzz_dir)
            .context(format!("unable to create {} dir", hfuzz_dir.display()))?;

        let src_dir = hfuzz_dir.join("src");
        fs::create_dir_all(&src_dir)
            .context(format!("unable to create {} dir", src_dir.display()))?;

        fs::copy(self.dir.join("Cargo.toml"), hfuzz_dir.join("Cargo.toml"))?;
        fs::copy(self.dir.join("template.rs"), hfuzz_dir.join("template.rs"))?;
        fs::copy(self.dir.join("src").join("lib.rs"), src_dir.join("lib.rs"))?;
        Ok(())
    }

    pub fn run(&self, target: String) -> Result<(), Error> {
        let corpora_dir = corpora_target(&target)?;

        prepare_targets_workspace()?;
        // create hfuzz folder inside workspace/
        self.prepare_fuzzer_workspace()?;
        // write all fuzz targets inside hfuzz folder
        write_fuzzer_target(&self.dir, &self.work_dir, &target)?;
        println!("[eth2diff] {}: {} created", self.name, target);

        let args = format!(
            "{} \
             {} \
             {}",
            if let Some(t) = self.timeout {
                format!("--run_time {}", t)
            } else {
                "".into()
            },
            if let Some(n) = self.thread {
                // Set number of thread
                format!("-n {}", n)
            } else {
                "".into()
            },
            env::var("HFUZZ_RUN_ARGS").unwrap_or_default()
        );

        // Honggfuzz will first build than run the fuzzer using cargo
        let fuzzer_bin = Command::new("cargo")
            .args(&["+nightly", "hfuzz", "run", &target])
            .env("HFUZZ_RUN_ARGS", &args)
            //.env("HFUZZ_BUILD_ARGS", "opt-level=3")
            .env("HFUZZ_INPUT", corpora_dir)
            .env(
                "ETH2FUZZ_BEACONSTATE",
                format!("{}", state_dir()?.display()),
            )
            .current_dir(&self.work_dir)
            .spawn()
            .context(format!("error starting {} to run {}", self.name, target))?
            .wait()
            .context(format!(
                "error while waiting for {} running {}",
                self.name, target
            ))?;

        if !fuzzer_bin.success() {
            Err(FuzzerQuit)?;
        }
        Ok(())
    }

    /// Build all targets with honggfuzz
    pub fn build_honggfuzz(&self) -> Result<(), Error> {
        for target in &get_targets()? {
            write_fuzzer_target(&self.dir, &self.work_dir, &target)?;
            println!("[eth2diff] {}: {} created", self.name, target);
        }
        let dir = &self.dir;

        println!("[eth2fuzz] {}: Start building", self.name);

        // Build fuzzing target
        let fuzzer_bin = Command::new("cargo")
            .args(&["+nightly", "hfuzz", "build"])
            .current_dir(&dir)
            .spawn()
            .context(format!("error building {} targets", self.name))?
            .wait()
            .context(format!("error while waiting for {} building", self.name))?;

        // Check if success
        if !fuzzer_bin.success() {
            Err(FuzzerQuit)?;
        }
        println!("[eth2fuzz] {}: building OK", self.name);
        Ok(())
    }
}

pub struct FuzzerAfl {
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

impl FuzzerAfl {
    /// Create a new FuzzerAfl
    pub fn new(timeout: Option<i32>, thread: Option<i32>) -> Result<FuzzerAfl, Error> {
        let cwd = env::current_dir().context("error getting current directory")?;
        let fuzzer = FuzzerAfl {
            name: "Afl++".to_string(),
            dir: cwd.join("fuzzer-afl"),
            work_dir: cwd.join("workspace").join("afl"),
            workspace_dir: cwd.join("workspace").join("afl").join("afl_workspace"),
            timeout: timeout,
            thread: thread,
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
        fs::copy(self.dir.join("src").join("lib.rs"), src_dir.join("lib.rs"))?;
        Ok(())
    }

    /// Build all targets with afl
    fn build_targets_afl(&self) -> Result<(), Error> {
        for target in &get_targets()? {
            self.build_afl(&target.to_string())?;
        }
        Ok(())
    }

    /// Build single target with afl
    pub fn build_afl(&self, target: &String) -> Result<(), Error> {
        prepare_targets_workspace()?;
        // create afl folder inside workspace/
        self.prepare_fuzzer_workspace()?;

        write_fuzzer_target(&self.dir, &self.work_dir, &target)?;

        let build_cmd = Command::new("cargo")
            .args(&["+nightly", "afl", "build", "--bin", &target]) // TODO: not sure we want to compile afl in "--release"
            .current_dir(&self.work_dir)
            .spawn()
            .context(format!(
                "error starting build for {} of {}",
                self.name, target
            ))?
            .wait()
            .context(format!(
                "error while waiting for build for {} of {}",
                self.name, target
            ))?;

        if !build_cmd.success() {
            Err(FuzzerQuit)?;
        }

        Ok(())
    }

    pub fn run(&self, target: String) -> Result<(), Error> {
        let dir = &self.work_dir;
        let corpora_dir = corpora_target(&target)?;

        self.build_afl(&target)?;

        // TODO - modify to use same corpus than other fuzzer
        let corpus_dir = &self.workspace_dir;
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
        if let Some(t) = self.timeout {
            args.push(format!("-V {}", t));
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
            .args(&["--", &format!("./target/debug/{}", target)])
            .env(
                "ETH2FUZZ_BEACONSTATE",
                format!("{}", state_dir()?.display()),
            )
            .current_dir(&dir)
            .spawn()
            .context(format!("error starting {:?} to run {}", self.name, target))?
            .wait()
            .context(format!(
                "error while waiting for {:?} running {}",
                self.name, target
            ))?;

        if !fuzzer_bin.success() {
            Err(FuzzerQuit)?;
        }
        Ok(())
    }
}

pub struct FuzzerLibfuzzer {
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

impl FuzzerLibfuzzer {
    /// Create a new FuzzerLibfuzzer
    pub fn new(timeout: Option<i32>, thread: Option<i32>) -> Result<FuzzerLibfuzzer, Error> {
        let cwd = env::current_dir().context("error getting current directory")?;
        let fuzzer = FuzzerLibfuzzer {
            name: "Libfuzzer".to_string(),
            dir: cwd.join("fuzzer-libfuzzer"),
            work_dir: cwd.join("workspace").join("libfuzzer"),
            workspace_dir: cwd
                .join("workspace")
                .join("libfuzzer")
                .join("libfuzzer_workspace"),
            timeout: timeout,
            thread: thread,
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
        fs::copy(self.dir.join("src").join("lib.rs"), src_dir.join("lib.rs"))?;
        Ok(())
    }

    pub fn run(&self, target: String) -> Result<(), Error> {
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

        for target in &get_targets()? {
            write_libfuzzer_target(&self.work_dir, target)?;
        }

        let fuzz_dir = self.work_dir.join("fuzz");
        let corpus_dir = corpora_target(&target)?;

        // create arguments
        // corpora dir
        // max_time if provided (i.e. continuously fuzzing)
        let mut args: Vec<String> = Vec::new();
        args.push(format!("{}", &corpus_dir.display()));
        if let Some(timeout) = self.timeout {
            args.push("--".to_string());
            args.push(format!("-max_total_time={}", timeout));
        };

        // Launch the fuzzer using cargo
        let fuzzer_bin = Command::new("cargo")
            .env(
                "ETH2FUZZ_BEACONSTATE",
                format!("{}", state_dir()?.display()),
            )
            .args(&["+nightly", "fuzz", "run", &target])
            .args(&args)
            .current_dir(&fuzz_dir)
            .spawn()
            .context(format!("error starting {:?} to run {}", self.name, target))?
            .wait()
            .context(format!(
                "error while waiting for {:?} running {}",
                self.name, target
            ))?;

        if !fuzzer_bin.success() {
            Err(FuzzerQuit)?;
        }
        Ok(())
    }
}

fn write_libfuzzer_target(fuzzer_dir: &PathBuf, target: &str) -> Result<(), Error> {
    use std::io::Write;

    let fuzz_dir = fuzzer_dir.join("fuzz");

    let template_path = fuzzer_dir.join("template.rs");
    let template = fs::read_to_string(&template_path).context(format!(
        "error reading template file {}",
        template_path.display()
    ))?;

    // use `cargo fuzz add` to add new bin inside Cargo.toml
    // and create fuzz_targets dir
    // and create target.rs
    let _ = Command::new("cargo")
        .args(&["+nightly", "fuzz", "add", &target])
        .current_dir(&fuzzer_dir)
        .spawn()
        .context(format!("error adding {}", target))?
        .wait()
        .context(format!("error while adding {}", target));

    let target_dir = fuzz_dir.join("fuzz_targets");

    let path = target_dir.join(&format!("{}.rs", target));

    let mut file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&path)
        .context(format!(
            "write_libfuzzer_target error writing fuzz target binary {}",
            path.display()
        ))?;

    let source = template.replace("###TARGET###", &target);
    file.write_all(source.as_bytes())?;
    Ok(())
}

/// Write the fuzzing target
///
/// Copy the fuzzer/template.rs
/// Replace ###TARGET### by the target
fn write_fuzzer_target(
    fuzzer_dir: &PathBuf,
    fuzzer_workdir: &PathBuf,
    target: &str,
) -> Result<(), Error> {
    use std::io::Write;

    let template_path = fuzzer_dir.join("template.rs");
    let template = fs::read_to_string(&template_path).context(format!(
        "error reading template file {}",
        template_path.display()
    ))?;

    let target_dir = fuzzer_workdir.join("src").join("bin");
    fs::create_dir_all(&target_dir).context(format!(
        "error creating fuzz target dir {}",
        target_dir.display()
    ))?;
    let path = target_dir.join(&format!("{}.rs", target));

    let mut file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&path)
        .context(format!(
            "error writing fuzz target binary {}",
            path.display()
        ))?;

    let source = template.replace("###TARGET###", &target);
    file.write_all(source.as_bytes())?;
    Ok(())
}
