use state_processing::{
    per_block_processing::{process_attester_slashings, VerifySignatures},
    BlockProcessingError,
};

use types::{AttesterSlashing, BeaconState, EthSpec, MainnetEthSpec, RelativeEpoch};

/// Run `process_attester_slashings`
pub fn process_attester_slashing(mut beaconstate: BeaconState<MainnetEthSpec>,
        attester_slashing: AttesterSlashing<MainnetEthSpec>)
            -> Result<(), BlockProcessingError> {
    let spec = MainnetEthSpec::default_spec();

    let state = &mut beaconstate;
    // Ensure the current epoch cache is built.
    // Required by slash_validator->initiate_validator_exit->get_churn_limit
    state.build_committee_cache(RelativeEpoch::Current, &spec)?;

    process_attester_slashings(
        &mut beaconstate,  // TODO - should it be state instead?
        &[attester_slashing],
        // TODO(gnattishness) check whether we validate these consistently
        VerifySignatures::False, // TODO - should we verify it?
        &spec,
    )?;

    Ok(())
}
