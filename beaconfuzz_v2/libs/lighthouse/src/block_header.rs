use state_processing::{
    per_block_processing::process_block_header as process_header, BlockProcessingError,
};

use types::{BeaconBlock, BeaconState, EthSpec, MainnetEthSpec, RelativeEpoch};

/// Run `process_block_header`
pub fn process_block_header(
    mut beaconstate: BeaconState<MainnetEthSpec>,
    block: BeaconBlock<MainnetEthSpec>,
    debug: bool,
) -> Result<BeaconState<MainnetEthSpec>, BlockProcessingError> {
    let spec = MainnetEthSpec::default_spec();

    // Ensure the current epoch cache is built.
    beaconstate.build_committee_cache(RelativeEpoch::Current, &spec)?;

    let ret = process_header(&mut beaconstate, &block, &spec);

    // print if processing goes well or not
    if debug {
        println!("[LIGHTHOUSE] {:?}", ret);
    }
    if let Err(e) = ret {
        Err(BlockProcessingError::from(e))
    } else {
        Ok(beaconstate)
    }
}
