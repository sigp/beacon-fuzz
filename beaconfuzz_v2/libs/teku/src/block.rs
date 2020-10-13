use ssz::Encode; //Decode
use ssz_derive::{Decode, Encode};

use crate::util::run_target;
use types::{BeaconState, MainnetEthSpec, SignedBeaconBlock};

#[derive(Decode, Encode)]
struct BlockTestCase {
    pub pre: BeaconState<MainnetEthSpec>,
    pub beacon_block: SignedBeaconBlock<MainnetEthSpec>,
}

pub fn process_block(
    beacon: &BeaconState<MainnetEthSpec>,
    beacon_block: &SignedBeaconBlock<MainnetEthSpec>,
    post: &[u8],
    debug: bool,
) -> bool {
    // create testcase ssz struct
    let target: BlockTestCase = BlockTestCase {
        pre: beacon.clone(),
        beacon_block: beacon_block.clone(),
    };

    let input_ssz = target.as_ssz_bytes();
    run_target(input_ssz.as_slice(), post, debug)
}
