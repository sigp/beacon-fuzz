use state_processing::{per_block_processing::process_deposit as real_process_deposit, BlockProcessingError};

use types::{BeaconState, Deposit, EthSpec, MainnetEthSpec};

    /// Run `process_deposit`
pub fn process_deposit(mut beaconstate: BeaconState<MainnetEthSpec>,
    deposit: Deposit)
        -> Result<(), BlockProcessingError> {
    let spec = MainnetEthSpec::default_spec();

    real_process_deposit(&mut beaconstate, &deposit, &spec, true)?;

    Ok(())
}
