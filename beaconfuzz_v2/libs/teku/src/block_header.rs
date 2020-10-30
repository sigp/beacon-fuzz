use ssz::Encode; //Decode
use ssz_derive::{Decode, Encode};

use crate::util::run_target;
use types::{BeaconBlock, BeaconState, MainnetEthSpec, Signature, SignedBeaconBlock};

#[derive(Decode, Encode)]
struct BlockHeaderTestCase {
    pub pre: BeaconState<MainnetEthSpec>,
    pub beacon_block: BeaconBlock<MainnetEthSpec>,
}

// TODO modify to take a SignedBeaconBlock instead?
pub fn process_block_header(
    beacon: &BeaconState<MainnetEthSpec>,
    beacon_block: &BeaconBlock<MainnetEthSpec>,
    post: &[u8],
    debug: bool,
) -> bool {
    // create testcase ssz struct
    // we need to wrap BeaconBlock into a SignedBeaconBlock
    let target: BlockHeaderTestCase = BlockHeaderTestCase {
        pre: beacon.clone(),
        beacon_block: beacon_block.clone(),
    };

    let input_ssz = target.as_ssz_bytes();
    run_target(input_ssz.as_slice(), post, debug)
}
