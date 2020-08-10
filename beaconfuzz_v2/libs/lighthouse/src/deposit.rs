use state_processing::{
    per_block_processing::process_deposit as lighthouse_process_deposit, BlockProcessingError,
};

use types::{BeaconState, Deposit, EthSpec, MainnetEthSpec};

pub fn process_deposit(
    mut beaconstate: BeaconState<MainnetEthSpec>,
    deposit: Deposit,
) -> Result<BeaconState<MainnetEthSpec>, BlockProcessingError> {
    let spec = MainnetEthSpec::default_spec();

    lighthouse_process_deposit(&mut beaconstate, &deposit, &spec, true)?;

    Ok(beaconstate)
}
