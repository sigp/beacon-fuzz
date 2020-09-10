use state_processing::{
    per_block_processing::{process_proposer_slashings, VerifySignatures},
    BlockProcessingError,
};

use types::{BeaconState, EthSpec, MainnetEthSpec, ProposerSlashing, RelativeEpoch};

pub fn process_proposer_slashing(
    mut beaconstate: BeaconState<MainnetEthSpec>,
    proposer_slashing: ProposerSlashing,
    debug: bool,
) -> Result<BeaconState<MainnetEthSpec>, BlockProcessingError> {
    let spec = MainnetEthSpec::default_spec();

    // Ensure the current epoch cache is built.
    beaconstate.build_committee_cache(RelativeEpoch::Current, &spec)?;

    let ret = process_proposer_slashings(
        &mut beaconstate,
        &[proposer_slashing],
        VerifySignatures::False,
        &spec,
    );

    // print if processing goes well or not
    if debug {
        println!("[LIGHTHOUSE] {:?}", ret);
    }
    if let Err(e) = ret {
        Err(e)
    } else {
        Ok(beaconstate)
    }
}
