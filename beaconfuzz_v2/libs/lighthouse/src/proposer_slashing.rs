use state_processing::{
    per_block_processing::{process_proposer_slashings, VerifySignatures},
    BlockProcessingError,
};

use types::{BeaconState, EthSpec, MainnetEthSpec, ProposerSlashing, RelativeEpoch};

pub fn process_proposer_slashing(
    mut beaconstate: BeaconState<MainnetEthSpec>,
    proposer_slashing: ProposerSlashing,
) -> Result<BeaconState<MainnetEthSpec>, BlockProcessingError> {
    let spec = MainnetEthSpec::default_spec();

    // Ensure the current epoch cache is built.
    beaconstate.build_committee_cache(RelativeEpoch::Current, &spec)?;

    process_proposer_slashings(
        &mut beaconstate,
        &[proposer_slashing],
        VerifySignatures::False,
        &spec,
    )?;

    Ok(beaconstate)
}
