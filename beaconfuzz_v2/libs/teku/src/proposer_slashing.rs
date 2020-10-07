use ssz::Encode; //Decode
use ssz_derive::{Decode, Encode};

use crate::util::run_target;
use types::{BeaconState, MainnetEthSpec, ProposerSlashing};

#[derive(Decode, Encode)]
struct ProposerSlashingTestCase {
    pub pre: BeaconState<MainnetEthSpec>,
    pub proposer_slashing: ProposerSlashing,
}

pub fn process_proposer_slashing(
    beacon: &BeaconState<MainnetEthSpec>,
    proposer_slashing: &ProposerSlashing,
    post: &[u8],
    debug: bool,
) -> bool {
    // create testcase ssz struct
    let target: ProposerSlashingTestCase = ProposerSlashingTestCase {
        pre: beacon.clone(),
        proposer_slashing: proposer_slashing.clone(),
    };

    let input_ssz = target.as_ssz_bytes();
    run_target(input_ssz.as_slice(), post, debug)
}
