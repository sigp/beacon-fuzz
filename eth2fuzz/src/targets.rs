use strum::IntoEnumIterator;

#[derive(Copy, Clone, Debug, EnumIter)]
pub enum Targets {
    // Lighthouse
    LighthouseAttestation,
    LighthouseAttesterSlashing,
    LighthouseBlock,
    LighthouseBlockHeader,
    LighthouseDeposit,
    LighthouseProposerSlashing,
    LighthouseVoluntaryExit,
    //LighthouseBeaconstate,
    LighthouseEnr,
    LighthouseBLS,
    LighthouseDiscv5Packet,
    // Lodestar
    LodestarAttestation,
    LodestarAttesterSlashing,
    LodestarBlock,
    LodestarBlockHeader,
    LodestarDeposit,
    LodestarProposerSlashing,
    LodestarVoluntaryExit,
    //LodestarBeaconstate,
    LodestarEnr,
    // Nimbus
    NimbusAttestation,
    NimbusAttesterSlashing,
    NimbusBlock,
    NimbusBlockHeader,
    NimbusDeposit,
    NimbusProposerSlashing,
    NimbusVoluntaryExit,
    //NimbusBeaconstate,
    NimbusEnr,
    // Prysm
    PrysmAttestation,
    PrysmAttesterSlashing,
    PrysmBlock,
    PrysmBlockHeader,
    PrysmDeposit,
    PrysmProposerSlashing,
    PrysmVoluntaryExit,
    // Teku
    TekuAttestation,
    TekuAttesterSlashing,
    TekuBlock,
    TekuBlockHeader,
    TekuDeposit,
    TekuProposerSlashing,
    TekuVoluntaryExit,
    TekuBLS,
}

impl Targets {
    pub fn name(&self) -> String {
        match &self {
            // Lighthouse
            Targets::LighthouseAttestation => "lighthouse_attestation",
            Targets::LighthouseAttesterSlashing => "lighthouse_attester_slashing",
            Targets::LighthouseBlock => "lighthouse_block",
            Targets::LighthouseBlockHeader => "lighthouse_block_header",
            Targets::LighthouseDeposit => "lighthouse_deposit",
            Targets::LighthouseProposerSlashing => "lighthouse_proposer_slashing",
            Targets::LighthouseVoluntaryExit => "lighthouse_voluntary_exit",
            //Targets::LighthouseBeaconstate => "lighthouse_beaconstate",
            Targets::LighthouseEnr => "lighthouse_enr",
            Targets::LighthouseBLS => "lighthouse_bls",
            Targets::LighthouseDiscv5Packet => "lighthouse_discv5_packet",
            //Lodestar
            Targets::LodestarAttestation => "lodestar_attestation",
            Targets::LodestarAttesterSlashing => "lodestar_attester_slashing",
            Targets::LodestarBlock => "lodestar_block",
            Targets::LodestarBlockHeader => "lodestar_block_header",
            Targets::LodestarDeposit => "lodestar_deposit",
            Targets::LodestarProposerSlashing => "lodestar_proposer_slashing",
            Targets::LodestarVoluntaryExit => "lodestar_voluntary_exit",
            //Targets::LodestarBeaconstate => "lodestar_beaconstate",
            Targets::LodestarEnr => "lodestar_enr",
            // Nimbus
            Targets::NimbusAttestation => "nimbus_attestation",
            Targets::NimbusAttesterSlashing => "nimbus_attester_slashing",
            Targets::NimbusBlock => "nimbus_block",
            Targets::NimbusBlockHeader => "nimbus_block_header",
            Targets::NimbusDeposit => "nimbus_deposit",
            Targets::NimbusProposerSlashing => "nimbus_proposer_slashing",
            Targets::NimbusVoluntaryExit => "nimbus_voluntary_exit",
            //Targets::NimbusBeaconstate => "nimbus_beaconstate",
            Targets::NimbusEnr => "nimbus_enr",
            // Prysm
            Targets::PrysmAttestation => "prysm_attestation",
            Targets::PrysmAttesterSlashing => "prysm_attester_slashing",
            Targets::PrysmBlock => "prysm_block",
            Targets::PrysmBlockHeader => "prysm_block_header",
            Targets::PrysmDeposit => "prysm_deposit",
            Targets::PrysmProposerSlashing => "prysm_proposer_slashing",
            Targets::PrysmVoluntaryExit => "prysm_voluntary_exit",
            // Teku
            Targets::TekuAttestation => "teku_attestation",
            Targets::TekuAttesterSlashing => "teku_attester_slashing",
            Targets::TekuBlock => "teku_block",
            Targets::TekuBlockHeader => "teku_block_header",
            Targets::TekuDeposit => "teku_deposit",
            Targets::TekuProposerSlashing => "teku_proposer_slashing",
            Targets::TekuVoluntaryExit => "teku_voluntary_exit",
            Targets::TekuBLS => "teku_bls",
        }
        .to_string()
    }

    pub fn corpora(&self) -> String {
        match &self {
            // Lighthouse
            Targets::LighthouseAttestation => "attestation",
            Targets::LighthouseAttesterSlashing => "attester_slashing",
            Targets::LighthouseBlock => "block",
            Targets::LighthouseBlockHeader => "block_header",
            Targets::LighthouseDeposit => "deposit",
            Targets::LighthouseProposerSlashing => "proposer_slashing",
            Targets::LighthouseVoluntaryExit => "voluntary_exit",
            //Targets::LighthouseBeaconstate => "beaconstate",
            Targets::LighthouseEnr => "enr",
            Targets::LighthouseBLS => "bls",
            Targets::LighthouseDiscv5Packet => "discv5_packet",
            //Lodestar
            Targets::LodestarAttestation => "attestation",
            Targets::LodestarAttesterSlashing => "attester_slashing",
            Targets::LodestarBlock => "block",
            Targets::LodestarBlockHeader => "block_header",
            Targets::LodestarDeposit => "deposit",
            Targets::LodestarProposerSlashing => "proposer_slashing",
            Targets::LodestarVoluntaryExit => "voluntary_exit",
            //Targets::LodestarBeaconstate => "beaconstate",
            Targets::LodestarEnr => "enr",
            // Nimbus
            Targets::NimbusAttestation => "attestation",
            Targets::NimbusAttesterSlashing => "attester_slashing",
            Targets::NimbusBlock => "block",
            Targets::NimbusBlockHeader => "block_header",
            Targets::NimbusDeposit => "deposit",
            Targets::NimbusProposerSlashing => "proposer_slashing",
            Targets::NimbusVoluntaryExit => "voluntary_exit",
            //Targets::NimbusBeaconstate => "beaconstate",
            Targets::NimbusEnr => "enr",
            // Prysm
            Targets::PrysmAttestation => "attestation",
            Targets::PrysmAttesterSlashing => "attester_slashing",
            Targets::PrysmBlock => "block",
            Targets::PrysmBlockHeader => "block_header",
            Targets::PrysmDeposit => "deposit",
            Targets::PrysmProposerSlashing => "proposer_slashing",
            Targets::PrysmVoluntaryExit => "voluntary_exit",
            // Teku
            Targets::TekuAttestation => "attestation",
            Targets::TekuAttesterSlashing => "attester_slashing",
            Targets::TekuBlock => "block",
            Targets::TekuBlockHeader => "block_header",
            Targets::TekuDeposit => "deposit",
            Targets::TekuProposerSlashing => "proposer_slashing",
            Targets::TekuVoluntaryExit => "voluntary_exit",
            Targets::TekuBLS => "bls",
        }
        .to_string()
    }

    pub fn language(&self) -> String {
        match &self {
            // Lighthouse
            Targets::LighthouseAttestation
            | Targets::LighthouseAttesterSlashing
            | Targets::LighthouseBlock
            | Targets::LighthouseBlockHeader
            | Targets::LighthouseDeposit
            | Targets::LighthouseProposerSlashing
            | Targets::LighthouseVoluntaryExit
            //| Targets::LighthouseBeaconstate
            | Targets::LighthouseEnr
            | Targets::LighthouseBLS
            | Targets::LighthouseDiscv5Packet => "rust",
            //Lodestar
            Targets::LodestarAttestation
            | Targets::LodestarAttesterSlashing
            | Targets::LodestarBlock
            | Targets::LodestarBlockHeader
            | Targets::LodestarDeposit
            | Targets::LodestarProposerSlashing
            | Targets::LodestarVoluntaryExit
            //| Targets::LodestarBeaconstate
            | Targets::LodestarEnr => "js",
            // Nimbus
            Targets::NimbusAttestation
            | Targets::NimbusAttesterSlashing
            | Targets::NimbusBlock
            | Targets::NimbusBlockHeader
            | Targets::NimbusDeposit
            | Targets::NimbusProposerSlashing
            | Targets::NimbusVoluntaryExit
            //| Targets::NimbusBeaconstate
            | Targets::NimbusEnr => "nim",
            // Prysm
            Targets::PrysmAttestation
            | Targets::PrysmAttesterSlashing
            | Targets::PrysmBlock
            | Targets::PrysmBlockHeader
            | Targets::PrysmDeposit
            | Targets::PrysmProposerSlashing
            | Targets::PrysmVoluntaryExit => "go",
            // Teku
            Targets::TekuAttestation
            | Targets::TekuAttesterSlashing
            | Targets::TekuBlock
            | Targets::TekuBlockHeader
            | Targets::TekuDeposit
            | Targets::TekuProposerSlashing
            | Targets::TekuVoluntaryExit
            | Targets::TekuBLS => "java",
        }
        .to_string()
    }
}

// Lighthouse_
pub fn get_lighthouse_targets() -> Vec<String> {
    let res: Vec<String> = Targets::iter()
        .filter(|target| target.language() == "rust")
        .map(|x| x.name())
        .collect();
    res
}

// Lodestar
pub fn get_lodestar_targets() -> Vec<String> {
    let res: Vec<String> = Targets::iter()
        .filter(|target| target.language() == "js")
        .map(|x| x.name())
        .collect();
    res
}

// Nimbus
pub fn get_nimbus_targets() -> Vec<String> {
    let res: Vec<String> = Targets::iter()
        .filter(|target| target.language() == "nim")
        .map(|x| x.name())
        .collect();
    res
}

// Prysm
pub fn get_prysm_targets() -> Vec<String> {
    let res: Vec<String> = Targets::iter()
        .filter(|target| target.language() == "go")
        .map(|x| x.name())
        .collect();
    res
}

// Teku
pub fn get_teku_targets() -> Vec<String> {
    let res: Vec<String> = Targets::iter()
        .filter(|target| target.language() == "java")
        .map(|x| x.name())
        .collect();
    res
}

pub fn get_targets() -> Vec<String> {
    Targets::iter().map(|x| x.name()).collect()
}
