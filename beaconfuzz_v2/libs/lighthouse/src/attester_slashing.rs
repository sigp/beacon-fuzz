use state_processing::{
    per_block_processing::{process_attester_slashings, VerifySignatures},
    BlockProcessingError,
};

use types::{AttesterSlashing, BeaconState, EthSpec, MainnetEthSpec, RelativeEpoch};

/// Run `process_attester_slashings`
pub fn process_attester_slashing(
    mut beaconstate: BeaconState<MainnetEthSpec>,
    attester_slashing: AttesterSlashing<MainnetEthSpec>,
) -> Result<BeaconState<MainnetEthSpec>, BlockProcessingError> {
    let spec = MainnetEthSpec::default_spec();

    // Ensure the current epoch cache is built.
    beaconstate.build_committee_cache(RelativeEpoch::Current, &spec)?;

    process_attester_slashings(
        &mut beaconstate,
        &[attester_slashing],
        VerifySignatures::False,
        &spec,
    )?;

    Ok(beaconstate)
}
