use state_processing::{
    per_block_processing::{process_attestations, VerifySignatures},
    BlockProcessingError,
};

use types::{Attestation, BeaconState, EthSpec, MainnetEthSpec};

/// Run `process_block_header`
pub fn process_attestation(mut beaconstate: BeaconState<MainnetEthSpec>,
        attestation: Attestation<MainnetEthSpec>)
            -> Result<(), BlockProcessingError> {

    let spec = MainnetEthSpec::default_spec();

    // TODO not certain whether we use beacon_node::beacon_chain::process_attestation,
    // or eth2::state_processing::per_block_processing::process_attestations
    // or possibly beacon_node:fork_choice
    // I think process_attestations, but only due to existing types etc, not proper understanding
    process_attestations(
        &mut beaconstate,
        &[attestation],
        VerifySignatures::True,
        &spec,
    )?;

    Ok(())
}
