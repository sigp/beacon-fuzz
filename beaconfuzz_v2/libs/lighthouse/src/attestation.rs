use state_processing::{
    per_block_processing::{process_attestations, VerifySignatures},
    BlockProcessingError,
};

use types::{Attestation, BeaconState, EthSpec, MainnetEthSpec, RelativeEpoch};

pub fn process_attestation(
    mut beaconstate: BeaconState<MainnetEthSpec>,
    attestation: Attestation<MainnetEthSpec>,
    debug: bool,
) -> Result<BeaconState<MainnetEthSpec>, BlockProcessingError> {
    let spec = MainnetEthSpec::default_spec();

    // Ensure the current epoch cache is built.
    //let state = &mut beaconstate;
    beaconstate.build_committee_cache(RelativeEpoch::Current, &spec)?;

    let ret = process_attestations(
        &mut beaconstate,
        &[attestation],
        VerifySignatures::False,
        &spec,
    );

    if debug {
        println!("[LIGHTHOUSE] process_attestation: {:?}", ret);
    };

    if let Err(e) = ret {
        Err(e)
    } else {
        Ok(beaconstate)
    }
}
