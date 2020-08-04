use ssz::Encode; //Decode
use ssz_derive::{Decode, Encode};

use types::{BeaconState, MainnetEthSpec, SignedBeaconBlock};

#[link(name = "nfuzz", kind = "static")]
extern "C" {
    fn NimMain();
    fn nfuzz_block(
        input_ptr: *mut u8,
        input_size: usize,
        output_ptr: *mut u8,
        output_size: *mut usize,
        disable_bls: bool,
    ) -> bool;
}

#[derive(Decode, Encode)]
struct BlockTestCase {
    pub pre: BeaconState<MainnetEthSpec>,
    pub beacon_block: SignedBeaconBlock<MainnetEthSpec>,
}

pub fn process_block(
    beacon: &BeaconState<MainnetEthSpec>,
    beacon_block: &SignedBeaconBlock<MainnetEthSpec>,
    post: &[u8],
) -> bool {
    let mut out: Vec<u8> = vec![0 as u8; post.len()];

    // create testcase ssz struct
    let target: BlockTestCase = BlockTestCase {
        pre: beacon.clone(),
        beacon_block: beacon_block.clone(),
    };

    let ssz_bytes = target.as_ssz_bytes();
    let ssz_bytes_len = ssz_bytes.len();
    let mut inn: Vec<u8> = ssz_bytes.into();
    let input_ptr: *mut u8 = inn.as_mut_ptr();
    let input_size: usize = ssz_bytes_len as usize;
    let output_ptr: *mut u8 = out.as_mut_ptr();
    let output_size: *mut usize = &mut (post.len() as usize);

    let res = unsafe {
        // initialize nim gc memory, types and stack
        NimMain();

        nfuzz_block(input_ptr, input_size, output_ptr, output_size, false)
    };

    assert_eq!(out, post);
    println!("[good]: {}", res);
    res
}

// Nimbus API libnfuzz (see here)
// https://github.com/status-im/nim-beacon-chain/blob/master/nfuzz/libnfuzz.h
