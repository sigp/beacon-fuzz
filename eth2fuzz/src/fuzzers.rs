use failure::{Error, ResultExt};
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use structopt::StructOpt;

use crate::targets::Targets;

#[derive(Fail, Debug)]
#[fail(display = "[eth2fuzz] Fuzzer quit")]
pub struct FuzzerQuit;

arg_enum! {
    #[derive(StructOpt, Debug, Clone, Copy, PartialEq, Eq)]
    /// All the fuzzers currently available
    pub enum Fuzzer {
        // Rust fuzzers
        Afl,
        Honggfuzz,
        Libfuzzer,
        // Javascript fuzzers
        Jsfuzz,
        // Nim fuzzers
        //NimAfl,
        NimLibfuzzer,
    }
}

arg_enum! {
    /// All the Sanitizers currently available
    ///
    /// NOTES: https://doc.rust-lang.org/nightly/unstable-book/compiler-flags/sanitizer.html
    #[derive(StructOpt, Debug, Clone, Copy, PartialEq, Eq)]
    pub enum Sanitizer {
        Address,
        Leak,
        Memory,
        Thread,
    }
}

impl Sanitizer {
    /// Sanitizer names used for RUSTFLAGS env variable.
    pub fn name(&self) -> String {
        match &self {
            Sanitizer::Address => "address".to_string(),
            Sanitizer::Leak => "leak".to_string(),
            Sanitizer::Memory => "memory".to_string(),
            Sanitizer::Thread => "thread".to_string(),
        }
    }
}

/// Configuration structure common for all fuzzers
#[derive(Debug, Default, Clone, Copy)]
pub struct FuzzerConfig {
    // Fuzzer timeout
    pub timeout: Option<i32>,
    // Number of fuzzing thread
    pub thread: Option<i32>,
    // Sanitizer
    pub sanitizer: Option<Sanitizer>,
    // Seed
    pub seed: Option<i32>,
}

/// Write the fuzzing target
///
/// Copy the fuzzer/template.rs
/// Replace ###TARGET### by the target
pub fn write_fuzzer_target(
    fuzzer_dir: &PathBuf,
    fuzzer_workdir: &PathBuf,
    target: Targets,
) -> Result<(), Error> {
    // Get the template for this target
    let template_path = fuzzer_dir.join(target.template());
    // Read this template file
    let template = fs::read_to_string(&template_path).context(format!(
        "error reading template file {}",
        template_path.display()
    ))?;

    // Target folder is different depending of the language
    let target_dir: PathBuf = match target.language().as_str() {
        "rust" => fuzzer_workdir.join("src").join("bin"),
        "js" => fuzzer_workdir.to_path_buf(),
        "nim" => fuzzer_workdir.to_path_buf(),
        _ => bail!("target_dir for this language not defined"),
    };

    // Try to create target directory
    fs::create_dir_all(&target_dir).context(format!(
        "error creating fuzz target dir {}",
        target_dir.display()
    ))?;

    // Check which file extension to use
    let ext: &str = match target.language().as_str() {
        "rust" => "rs",
        "js" => "js",
        "nim" => "nim",
        _ => bail!("ext for this language not defined"),
    };

    let path = target_dir.join(&format!("{}.{}", target.name(), ext));

    // Create the target harness file
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&path)
        .context(format!(
            "error writing fuzz target binary {}",
            path.display()
        ))?;

    // Replace this pattern in the template by the target name
    let source = template.replace("###TARGET###", &target.name());
    // Write in the file
    file.write_all(source.as_bytes())?;
    Ok(())
}
