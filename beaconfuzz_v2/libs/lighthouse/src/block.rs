use state_processing::{per_block_processing, BlockProcessingError, BlockSignatureStrategy};

use types::{BeaconState, EthSpec, MainnetEthSpec, RelativeEpoch, SignedBeaconBlock};

pub fn process_block(
    mut beaconstate: BeaconState<MainnetEthSpec>,
    block: SignedBeaconBlock<MainnetEthSpec>,
    validate_state_root: bool,
    debug: bool,
) -> Result<BeaconState<MainnetEthSpec>, BlockProcessingError> {
    let spec = MainnetEthSpec::default_spec();

    beaconstate.build_all_caches(&spec)?;
    let result = {
        /* not good for fuzzing (in some spectests cases, this can loop for 65k iteration )
        while state.slot < block.slot() {
            // TODO(gnattishness) handle option
            // requires implementation of an error trait that I can specify as the
            // return type
            per_slot_processing(&mut state, None, spec).unwrap();
        }
        */
        beaconstate.build_committee_cache(RelativeEpoch::Current, &spec)?;

        let ret = per_block_processing(
            &mut beaconstate,
            &block,
            None,
            BlockSignatureStrategy::NoVerification, //VerifyIndividual,
            &spec,
        );

        if debug {
            println!("[LIGHTHOUSE] {:?}", ret);
        }

        if let Err(e) = ret {
            return Err(e);
        }

        beaconstate
    };

    if !validate_state_root || block.state_root() == result.canonical_root() {
        Ok(result)
    } else {
        Err(BlockProcessingError::StateRootMismatch)
    }
}
