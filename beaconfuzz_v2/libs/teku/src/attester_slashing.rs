use ssz::Encode; //Decode
use ssz_derive::{Decode, Encode};

use crate::util::run_target;
use types::{AttesterSlashing, BeaconState, MainnetEthSpec};

// TODO move to common types/util crate?
#[derive(Decode, Encode)]
struct AttesterSlashingTestCase {
    pub pre: BeaconState<MainnetEthSpec>,
    pub attester_slashing: AttesterSlashing<MainnetEthSpec>,
}

pub fn process_attester_slashing(
    beacon: &BeaconState<MainnetEthSpec>,
    attester_slashing: &AttesterSlashing<MainnetEthSpec>,
    post: &[u8],
    debug: bool,
) -> bool {
    // create testcase ssz struct
    let target: AttesterSlashingTestCase = AttesterSlashingTestCase {
        pre: beacon.clone(),
        attester_slashing: attester_slashing.clone(),
    };

    let input_ssz = target.as_ssz_bytes();
    run_target(input_ssz.as_slice(), post, debug)
}
