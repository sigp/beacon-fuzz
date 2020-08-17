use state_processing::{
    per_block_processing::process_block_header as process_header, BlockProcessingError,
};

use types::{BeaconBlock, BeaconState, EthSpec, MainnetEthSpec};

/// Run `process_block_header`
pub fn process_block_header(
    mut beaconstate: BeaconState<MainnetEthSpec>,
    block: BeaconBlock<MainnetEthSpec>,
) -> Result<BeaconState<MainnetEthSpec>, BlockProcessingError> {
    let spec = MainnetEthSpec::default_spec();

    process_header(&mut beaconstate, &block, &spec)?;

    Ok(beaconstate)
}
