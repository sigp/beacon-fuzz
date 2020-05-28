use failure::{Error, ResultExt};
use std::fs;
use std::path::PathBuf;
use structopt::StructOpt;

use crate::targets::Targets;

#[derive(Fail, Debug)]
#[fail(display = "[eth2fuzz] Fuzzer quit")]
pub struct FuzzerQuit;

arg_enum! {
    #[derive(StructOpt, Debug, Clone, Copy, PartialEq, Eq)]
    pub enum Fuzzer {
        Afl,
        Honggfuzz,
        Libfuzzer,
        Jsfuzz,
        NimAfl,
        NimLibfuzzer,
    }
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
    use std::io::Write;

    let template_path = fuzzer_dir.join(target.template());
    let template = fs::read_to_string(&template_path).context(format!(
        "error reading template file {}",
        template_path.display()
    ))?;

    let target_dir: PathBuf = match target.language().as_str() {
        "rust" => fuzzer_workdir.join("src").join("bin"),
        "js" => fuzzer_workdir.to_path_buf(),
        "nim" => fuzzer_workdir.to_path_buf(),
        _ => bail!("target_dir for this language not defined"),
    };

    fs::create_dir_all(&target_dir).context(format!(
        "error creating fuzz target dir {}",
        target_dir.display()
    ))?;

    let ext: &str = match target.language().as_str() {
        "rust" => "rs",
        "js" => "js",
        "nim" => "nim",
        _ => bail!("ext for this language not defined"),
    };

    let path = target_dir.join(&format!("{}.{}", target.name(), ext));

    let mut file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&path)
        .context(format!(
            "error writing fuzz target binary {}",
            path.display()
        ))?;

    let source = template.replace("###TARGET###", &target.name());
    file.write_all(source.as_bytes())?;
    Ok(())
}
