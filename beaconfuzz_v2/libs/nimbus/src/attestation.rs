use ssz::Encode; //Decode
use ssz_derive::{Decode, Encode};

use types::{Attestation, BeaconState, MainnetEthSpec};

#[link(name = "nfuzz", kind = "static")]
extern "C" {
    fn nfuzz_attestation(
        input_ptr: *mut u8,
        input_size: usize,
        output_ptr: *mut u8,
        output_size: *mut usize,
        disable_bls: bool,
    ) -> bool;
}

#[derive(Decode, Encode)]
struct AttestationTestCase {
    pre: BeaconState<MainnetEthSpec>,
    attestation: Attestation<MainnetEthSpec>,
}

use crate::debug::dump_post_state;

pub fn process_attestation(
    beacon: &BeaconState<MainnetEthSpec>,
    attest: &Attestation<MainnetEthSpec>,
    post: &[u8],
    disable_bls: bool,
    debug: bool,
) -> bool {
    let mut out: Vec<u8> = vec![0 as u8; post.len()];

    // create testcase ssz struct
    let target: AttestationTestCase = AttestationTestCase {
        pre: beacon.clone(),
        attestation: attest.clone(),
    };

    let ssz_bytes = target.as_ssz_bytes();
    let ssz_bytes_len = ssz_bytes.len();
    let mut inn: Vec<u8> = ssz_bytes.into();
    let input_ptr: *mut u8 = inn.as_mut_ptr();
    let input_size: usize = ssz_bytes_len as usize;
    let output_ptr: *mut u8 = out.as_mut_ptr();
    let output_size: *mut usize = &mut (post.len() as usize);

    let res =
        unsafe { nfuzz_attestation(input_ptr, input_size, output_ptr, output_size, disable_bls) };

    // dump post files for debugging
    if debug {
        dump_post_state(&post, &out);
    }

    // If error triggered during processing, we return immediately
    if !res {
        return res;
    }

    // Verify nimbus's post is equal to lighthouse's post
    assert!(out == post, "[NIMBUS] Mismatch post");
    res
}
