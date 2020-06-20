use failure::{Error, ResultExt};
use std::env;
use std::fs;
use std::path::PathBuf;

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
    //fs::create_dir_all(&p).context("unable to create workspace dir".to_string())?;
    Ok(p)
}

pub fn corpora_dir() -> Result<PathBuf, Error> {
    let p = workspace_dir()?.join("corpora");
    Ok(p)
}

pub fn state_dir() -> Result<PathBuf, Error> {
    let seed_dir = corpora_dir()?.join("beaconstate");
    fs::create_dir_all(&seed_dir)
        .context("unable to create corpora/beaconstate dir".to_string())?;
    Ok(seed_dir)
}
