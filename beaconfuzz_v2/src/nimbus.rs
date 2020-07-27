// use types::{BeaconState, MainnetEthSpec};

use ssz::Encode; //Decode
use ssz_derive::{Decode, Encode};

use types::{Attestation, BeaconState, MainnetEthSpec};

#[link(name = "nfuzz", kind = "static")]
extern "C" {
    fn NimMain();
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
    pub pre: BeaconState<MainnetEthSpec>,
    pub attestation: Attestation<MainnetEthSpec>,
}

pub fn process_attestation(
    beacon: &BeaconState<MainnetEthSpec>,
    attest: &Attestation<MainnetEthSpec>,
    post: &[u8],
) -> Vec<u8> {
    // beacon: &[u8], attest: &[u8],
    //let out: Vec<u8> = Vec::with_capacity(post.len());
    let mut out: Vec<u8> = vec![0 as u8; post.len()];

    // create testcase ssz struct
    let target: AttestationTestCase = AttestationTestCase {
        pre: beacon.clone(),
        attestation: attest.clone(),
    };

    let ssz_bytes = target.as_ssz_bytes();

    println!("{:?}", ssz_bytes.as_ptr());
    println!("{:?}", ssz_bytes.len());
    println!("{:?}", out.as_ptr());
    println!("{:?}", post.len());

    let ssz_bytes_len = ssz_bytes.len();
    let mut inn: Vec<u8> = ssz_bytes.into();
    let input_ptr: *mut u8 = inn.as_mut_ptr();
    let input_size: usize = ssz_bytes_len as usize;
    let output_ptr: *mut u8 = out.as_mut_ptr();
    let output_size: *mut usize = &mut (post.len() as usize);

    let res = unsafe {
        // initialize nim gc memory, types and stack
        NimMain();

        nfuzz_attestation(input_ptr, input_size, output_ptr, output_size, false)
    };

    assert_eq!(out, post);
    println!("[good]: {}", res);
    out
}

// Nimbus API libnfuzz (see here)
// https://github.com/status-im/nim-beacon-chain/blob/master/nfuzz/libnfuzz.h
