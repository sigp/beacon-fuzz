use state_processing::BlockProcessingError;

use types::{
    Attestation, AttesterSlashing, BeaconBlock, BeaconState, Deposit, MainnetEthSpec,
    ProposerSlashing, SignedBeaconBlock, SignedVoluntaryExit,
};

use ssz::Decode; // Encode

/// Decode SSZ-encoded `Attestation` bytes
/// - input: SSZ-encoded bytes
/// - output: Ok(Attestation) or Err()
pub fn ssz_attestation(ssz_bytes: &[u8]) -> Result<Attestation<MainnetEthSpec>, ssz::DecodeError> {
    Ok(Attestation::from_ssz_bytes(&ssz_bytes)?)
}

pub fn ssz_attester_slashing(
    ssz_bytes: &[u8],
) -> Result<AttesterSlashing<MainnetEthSpec>, ssz::DecodeError> {
    Ok(AttesterSlashing::from_ssz_bytes(&ssz_bytes)?)
}

pub fn ssz_block(ssz_bytes: &[u8]) -> Result<SignedBeaconBlock<MainnetEthSpec>, ssz::DecodeError> {
    Ok(SignedBeaconBlock::from_ssz_bytes(&ssz_bytes)?)
}

pub fn ssz_block_header(ssz_bytes: &[u8]) -> Result<BeaconBlock<MainnetEthSpec>, ssz::DecodeError> {
    Ok(BeaconBlock::from_ssz_bytes(&ssz_bytes)?)
}

pub fn ssz_deposit(ssz_bytes: &[u8]) -> Result<Deposit, ssz::DecodeError> {
    Ok(Deposit::from_ssz_bytes(&ssz_bytes)?)
}

pub fn ssz_proposer_slashing(ssz_bytes: &[u8]) -> Result<ProposerSlashing, ssz::DecodeError> {
    Ok(ProposerSlashing::from_ssz_bytes(&ssz_bytes)?)
}

pub fn ssz_voluntary_exit(ssz_bytes: &[u8]) -> Result<SignedVoluntaryExit, ssz::DecodeError> {
    Ok(SignedVoluntaryExit::from_ssz_bytes(&ssz_bytes)?)
}

pub fn ssz_beaconstate(ssz_bytes: &[u8]) -> Result<BeaconState<MainnetEthSpec>, ssz::DecodeError> {
    Ok(BeaconState::from_ssz_bytes(&ssz_bytes)?)
}

pub mod attestation;
pub fn process_attestation(
    beaconstate: BeaconState<MainnetEthSpec>,
    attestation: Attestation<MainnetEthSpec>,
) -> Result<BeaconState<MainnetEthSpec>, BlockProcessingError> {
    self::attestation::process_attestation(beaconstate, attestation)
}

pub mod attester_slashing;
pub fn process_attester_slashing(
    beaconstate: BeaconState<MainnetEthSpec>,
    attester_slashing: AttesterSlashing<MainnetEthSpec>,
) -> Result<BeaconState<MainnetEthSpec>, BlockProcessingError> {
    self::attester_slashing::process_attester_slashing(beaconstate, attester_slashing)
}

pub mod block;
pub fn process_block(
    beaconstate: BeaconState<MainnetEthSpec>,
    block: SignedBeaconBlock<MainnetEthSpec>,
) -> Result<BeaconState<MainnetEthSpec>, BlockProcessingError> {
    self::block::process_block(beaconstate, block, false)
}

pub mod block_header;
pub fn process_block_header(
    beaconstate: BeaconState<MainnetEthSpec>,
    block: BeaconBlock<MainnetEthSpec>,
) -> Result<BeaconState<MainnetEthSpec>, BlockProcessingError> {
    self::block_header::process_block_header(beaconstate, block)
}

pub mod deposit;
pub fn process_deposit(
    beaconstate: BeaconState<MainnetEthSpec>,
    deposit: Deposit,
) -> Result<BeaconState<MainnetEthSpec>, BlockProcessingError> {
    self::deposit::process_deposit(beaconstate, deposit)
}

pub mod proposer_slashing;
pub fn process_proposer_slashing(
    beaconstate: BeaconState<MainnetEthSpec>,
    prop: ProposerSlashing,
) -> Result<BeaconState<MainnetEthSpec>, BlockProcessingError> {
    self::proposer_slashing::process_proposer_slashing(beaconstate, prop)
}

pub mod voluntary_exit;
pub fn process_voluntary_exit(
    beaconstate: BeaconState<MainnetEthSpec>,
    exit: SignedVoluntaryExit,
) -> Result<BeaconState<MainnetEthSpec>, BlockProcessingError> {
    self::voluntary_exit::process_voluntary_exit(beaconstate, exit)
}
