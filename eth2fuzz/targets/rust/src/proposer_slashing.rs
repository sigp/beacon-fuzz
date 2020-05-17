use state_processing::{
    per_block_processing::{process_proposer_slashings, VerifySignatures},
    BlockProcessingError,
};

use types::{BeaconState, EthSpec, MainnetEthSpec, ProposerSlashing, RelativeEpoch};

    /// Run `process_proposer_slashings`
pub fn process_proposer_slashing(mut beaconstate: BeaconState<MainnetEthSpec>,
    proposer_slashing: ProposerSlashing)
        -> Result<(), BlockProcessingError> {
    let spec = MainnetEthSpec::default_spec();
    //let mut state = &mut self.pre;
    // Ensure the current epoch cache is built.
    // Required by slash_validator->initiate_validator_exit->get_churn_limit
    beaconstate.build_committee_cache(RelativeEpoch::Current, &spec)?;

    process_proposer_slashings(
        &mut beaconstate,
        &[proposer_slashing],
        // TODO(gnattishness) check whether we validate these consistently
        VerifySignatures::False,
        &spec,
    )?;

    Ok(())
}
