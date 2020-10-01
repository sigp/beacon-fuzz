use ssz::Encode; //Decode
use ssz_derive::{Decode, Encode};

use types::{Attestation, BeaconState, MainnetEthSpec};

// TODO move to common types/util crate?
#[derive(Decode, Encode)]
struct AttestationTestCase {
    pre: BeaconState<MainnetEthSpec>,
    attestation: Attestation<MainnetEthSpec>,
}

use crate::util::run_target;

pub fn process_attestation(
    beacon: &BeaconState<MainnetEthSpec>,
    attest: &Attestation<MainnetEthSpec>,
    post: &[u8],
    debug: bool,
) -> bool {
    // create testcase ssz struct
    let target: AttestationTestCase = AttestationTestCase {
        pre: beacon.clone(),
        attestation: attest.clone(),
    };

    let input_ssz = target.as_ssz_bytes();
    run_target(input_ssz.as_slice(), post, debug)
}
