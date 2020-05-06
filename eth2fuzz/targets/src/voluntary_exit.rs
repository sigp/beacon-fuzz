use state_processing::{
    per_block_processing::{process_exits, VerifySignatures},
    BlockProcessingError,
};

use types::{BeaconState, EthSpec, MainnetEthSpec, SignedVoluntaryExit};

/// Run `process_exits`
pub fn process_voluntary_exit(mut beaconstate: BeaconState<MainnetEthSpec>,
    voluntary_exit: SignedVoluntaryExit)
        -> Result<(), BlockProcessingError> {
    let spec = MainnetEthSpec::default_spec();

    process_exits(
        &mut beaconstate,
        &[voluntary_exit],
        // TODO(gnattishness) check whether we validate these consistently
        VerifySignatures::False,
        &spec,
    )?;

    Ok(())
}
