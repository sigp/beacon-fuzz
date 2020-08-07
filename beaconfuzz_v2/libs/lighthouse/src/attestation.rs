use state_processing::{
    per_block_processing::{process_attestations, VerifySignatures},
    BlockProcessingError,
};

use types::{Attestation, BeaconState, EthSpec, MainnetEthSpec};

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
