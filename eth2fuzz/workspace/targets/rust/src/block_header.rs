use state_processing::{
    per_block_processing::{process_block_header},
    BlockProcessingError,
};

use types::{BeaconBlock, BeaconState, EthSpec, MainnetEthSpec};

/// Run `process_block_header`
pub fn process_header(mut beaconstate: BeaconState<MainnetEthSpec>,
    block: BeaconBlock<MainnetEthSpec>)
        -> Result<(), BlockProcessingError> {
    let spec = MainnetEthSpec::default_spec();

    process_block_header(&mut beaconstate, &block, &spec)?;

    Ok(())
}
