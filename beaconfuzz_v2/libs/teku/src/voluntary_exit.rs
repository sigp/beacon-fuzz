use ssz::Encode; //Decode
use ssz_derive::{Decode, Encode};

use crate::util::run_target;
use types::{BeaconState, MainnetEthSpec, SignedVoluntaryExit};

#[derive(Decode, Encode)]
struct VoluntaryExitTestCase {
    pub pre: BeaconState<MainnetEthSpec>,
    pub exit: SignedVoluntaryExit,
}

pub fn process_voluntary_exit(
    beacon: &BeaconState<MainnetEthSpec>,
    exit: &SignedVoluntaryExit,
    post: &[u8],
    debug: bool,
) -> bool {
    // create testcase ssz struct
    let target: VoluntaryExitTestCase = VoluntaryExitTestCase {
        pre: beacon.clone(),
        exit: exit.clone(),
    };

    let input_ssz = target.as_ssz_bytes();
    run_target(input_ssz.as_slice(), post, debug)
}
