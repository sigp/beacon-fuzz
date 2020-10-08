use state_processing::{
    per_block_processing::process_deposit as lighthouse_process_deposit, BlockProcessingError,
};

use types::{BeaconState, Deposit, EthSpec, MainnetEthSpec, RelativeEpoch};

pub fn process_deposit(
    mut beaconstate: BeaconState<MainnetEthSpec>,
    deposit: Deposit,
    debug: bool,
) -> Result<BeaconState<MainnetEthSpec>, BlockProcessingError> {
    let spec = MainnetEthSpec::default_spec();

    // Ensure the current epoch cache is built.
    beaconstate.build_committee_cache(RelativeEpoch::Current, &spec)?;

    let ret = lighthouse_process_deposit(&mut beaconstate, &deposit, &spec, true);

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
