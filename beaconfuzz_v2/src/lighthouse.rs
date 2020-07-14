use state_processing::{
    per_block_processing::{process_attestations, VerifySignatures},
    BlockProcessingError,
};

use types::{Attestation, BeaconState, EthSpec, MainnetEthSpec};

use ssz::Decode; // Encode

/// Decode SSZ-encoded `Attestation` bytes
/// - input: SSZ-encoded bytes
/// - output: Ok(Attestation) or Err()
pub fn ssz_attestation(ssz_bytes: &[u8]) -> Result<Attestation<MainnetEthSpec>, ssz::DecodeError> {
    Ok(Attestation::from_ssz_bytes(&ssz_bytes)?)
}

pub fn ssz_beaconstate(ssz_bytes: &[u8]) -> Result<BeaconState<MainnetEthSpec>, ssz::DecodeError> {
    Ok(BeaconState::from_ssz_bytes(&ssz_bytes)?)
}

pub fn process_attestation(
    mut beaconstate: BeaconState<MainnetEthSpec>,
    attestation: Attestation<MainnetEthSpec>,
) -> Result<BeaconState<MainnetEthSpec>, BlockProcessingError> {
    let spec = MainnetEthSpec::default_spec();

    process_attestations(
        &mut beaconstate,
        &[attestation],
        VerifySignatures::True,
        &spec,
    )?;

    Ok(beaconstate)
}
