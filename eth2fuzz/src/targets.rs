use failure::Error;
use strum::IntoEnumIterator;

use crate::env::{targets_dir, workspace_dir};
use crate::utils::copy_dir;

#[derive(Copy, Clone, Debug, EnumIter)]
pub enum Targets {
    LighthouseAttestation,
    LighthouseAttesterSlashing,
    LighthouseBlock,
    LighthouseBlockHeader,
    LighthouseDeposit,
    LighthouseProposerSlashing,
    LighthouseVoluntaryExit,
    LighthouseBeaconstate,
    LighthouseEnr,
    LighthouseBLS,
    LodestarAttestation,
    LodestarAttesterSlashing,
    LodestarBlock,
    LodestarBlockHeader,
    LodestarDeposit,
    LodestarProposerSlashing,
    LodestarVoluntaryExit,
    LodestarBeaconstate,
}

impl Targets {
    pub fn name(&self) -> String {
        let name = match &self {
            // Lighthouse
            Targets::LighthouseAttestation => "lighthouse_attestation",
            Targets::LighthouseAttesterSlashing => "lighthouse_attester_slashing",
            Targets::LighthouseBlock => "lighthouse_block",
            Targets::LighthouseBlockHeader => "lighthouse_block_header",
            Targets::LighthouseDeposit => "lighthouse_deposit",
            Targets::LighthouseProposerSlashing => "lighthouse_proposer_slashing",
            Targets::LighthouseVoluntaryExit => "lighthouse_voluntary_exit",
            Targets::LighthouseBeaconstate => "lighthouse_beaconstate",
            Targets::LighthouseEnr => "lighthouse_enr",
            Targets::LighthouseBLS => "lighthouse_bls",
            //Lodestar
            Targets::LodestarAttestation => "lodestar_attestation",
            Targets::LodestarAttesterSlashing => "lodestar_attester_slashing",
            Targets::LodestarBlock => "lodestar_block",
            Targets::LodestarBlockHeader => "lodestar_block_header",
            Targets::LodestarDeposit => "lodestar_deposit",
            Targets::LodestarProposerSlashing => "lodestar_proposer_slashing",
            Targets::LodestarVoluntaryExit => "lodestar_voluntary_exit",
            Targets::LodestarBeaconstate => "lodestar_beaconstate",
        };
        name.to_string()
    }

    pub fn corpora(&self) -> String {
        let corpora_name = match &self {
            // Lighthouse
            Targets::LighthouseAttestation => "attestation",
            Targets::LighthouseAttesterSlashing => "attester_slashing",
            Targets::LighthouseBlock => "block",
            Targets::LighthouseBlockHeader => "block_header",
            Targets::LighthouseDeposit => "deposit",
            Targets::LighthouseProposerSlashing => "proposer_slashing",
            Targets::LighthouseVoluntaryExit => "voluntary_exit",
            Targets::LighthouseBeaconstate => "beaconstate",
            Targets::LighthouseEnr => "enr",
            Targets::LighthouseBLS => "bls",
            //Lodestar
            Targets::LodestarAttestation => "attestation",
            Targets::LodestarAttesterSlashing => "attester_slashing",
            Targets::LodestarBlock => "block",
            Targets::LodestarBlockHeader => "block_header",
            Targets::LodestarDeposit => "deposit",
            Targets::LodestarProposerSlashing => "proposer_slashing",
            Targets::LodestarVoluntaryExit => "voluntary_exit",
            Targets::LodestarBeaconstate => "beaconstate",
        };
        corpora_name.to_string()
    }

    // TODO - change templae enr and bls and beaconstate
    pub fn template(&self) -> String {
        let template_name = match &self {
            // Lighthouse
            Targets::LighthouseAttestation
            | Targets::LighthouseAttesterSlashing
            | Targets::LighthouseBlock
            | Targets::LighthouseBlockHeader
            | Targets::LighthouseDeposit
            | Targets::LighthouseProposerSlashing
            | Targets::LighthouseVoluntaryExit => "template.rs",
            Targets::LighthouseBeaconstate | Targets::LighthouseEnr | Targets::LighthouseBLS => {
                "simple_template.rs"
            }
            //Lodestar
            Targets::LodestarAttestation
            | Targets::LodestarAttesterSlashing
            | Targets::LodestarBlock
            | Targets::LodestarBlockHeader
            | Targets::LodestarDeposit
            | Targets::LodestarProposerSlashing
            | Targets::LodestarVoluntaryExit
            | Targets::LodestarBeaconstate => "simple_template.js",
        };
        template_name.to_string()
    }

    pub fn language(&self) -> String {
        let lang = match &self {
            // Lighthouse
            Targets::LighthouseAttestation
            | Targets::LighthouseAttesterSlashing
            | Targets::LighthouseBlock
            | Targets::LighthouseBlockHeader
            | Targets::LighthouseDeposit
            | Targets::LighthouseProposerSlashing
            | Targets::LighthouseVoluntaryExit
            | Targets::LighthouseBeaconstate
            | Targets::LighthouseEnr
            | Targets::LighthouseBLS => "rust",
            //Lodestar
            Targets::LodestarAttestation
            | Targets::LodestarAttesterSlashing
            | Targets::LodestarBlock
            | Targets::LodestarBlockHeader
            | Targets::LodestarDeposit
            | Targets::LodestarProposerSlashing
            | Targets::LodestarVoluntaryExit
            | Targets::LodestarBeaconstate => "js",
        };
        lang.to_string()
    }
}

pub fn get_targets() -> Vec<String> {
    Targets::iter().map(|x| x.name()).collect()
}

pub fn prepare_targets_workspace() -> Result<(), Error> {
    let from = targets_dir()?;
    let workspace = workspace_dir()?;
    copy_dir(from, workspace)?;
    Ok(())
}
