use crate::strum::IntoEnumIterator;

use failure::{Error, ResultExt};
use std::fs;
use std::path::PathBuf;
use std::process::Command;

use crate::env::root_dir;
use crate::fuzzers::FuzzerQuit;

use crate::targets::{get_targets, prepare_targets_workspace, Targets};
use crate::utils::did_you_mean;

pub fn prepare_debug_workspace(out_dir: &str) -> Result<(), Error> {
    let debug_init_dir = root_dir()?.join("debug");
    let dir = root_dir()?.join("workspace");

    let debug_dir = dir.join(out_dir);
    fs::create_dir_all(&debug_dir)
        .context(format!("unable to create {} dir", debug_dir.display()))?;

    let src_dir = debug_dir.join("src");
    fs::create_dir_all(&src_dir).context(format!("unable to create {} dir", src_dir.display()))?;

    fs::copy(
        debug_init_dir.join("Cargo.toml"),
        debug_dir.join("Cargo.toml"),
    )?;
    fs::copy(
        debug_init_dir.join("src").join("lib.rs"),
        src_dir.join("lib.rs"),
    )?;
    Ok(())
}

// TODO - move part of this function to main.rs
// TODO - to specific to Rust
pub fn run_debug(target: String) -> Result<(), Error> {
    let target = match Targets::iter().find(|x| x.name() == target) {
        None => bail!(
            "Don't know target `{}`. {}",
            target,
            if let Some(alt) = did_you_mean(&target, &get_targets()) {
                format!("Did you mean `{}`?", alt)
            } else {
                "".into()
            }
        ),
        Some(t) => t,
    };

    let debug_dir = root_dir()?.join("workspace").join("debug");

    prepare_targets_workspace()?;
    prepare_debug_workspace("debug")?;

    write_debug_target(debug_dir.clone(), target)?;

    let debug_bin = Command::new("cargo")
        .args(&[
            "+nightly",
            "build",
            "--bin",
            &format!("debug_{}", target.name()),
        ])
        .current_dir(&debug_dir)
        .spawn()
        .context(format!("error starting {}", target.name()))?
        .wait()
        .context(format!("error while waiting for {}", target.name()))?;

    if !debug_bin.success() {
        Err(FuzzerQuit)?;
    }
    println!(
        "[WARF] Debug: {} compiled",
        &format!("debug_{}", target.name())
    );
    Ok(())
}

pub fn write_debug_target(debug_dir: PathBuf, target: Targets) -> Result<(), Error> {
    use std::io::Write;

    // TODO - make it cleaner
    let template_path = root_dir()?
        .join("debug")
        .join(format!("debug_{}", target.template()));
    let template = fs::read_to_string(&template_path).context(format!(
        "error reading debug template file {}",
        template_path.display()
    ))?;

    let target_dir: PathBuf = match target.language().as_str() {
        "rust" => debug_dir.join("src").join("bin"),
        "js" => debug_dir.to_path_buf(),
        _ => bail!("target_dir for this language not defined"),
    };

    fs::create_dir_all(&target_dir).context(format!(
        "error creating debug target dir {}",
        target_dir.display()
    ))?;

    let ext: &str = match target.language().as_str() {
        "rust" => "rs",
        "js" => "js",
        _ => bail!("ext for this language not defined"),
    };
    let path = target_dir.join(&format!("debug_{}.{}", target.name(), ext));

    let mut file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&path)
        .context(format!(
            "error writing debug target binary {}",
            path.display()
        ))?;

    let source = template.replace("###TARGET###", &target.name());
    file.write_all(source.as_bytes())?;
    Ok(())
}
