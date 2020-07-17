// use types::{BeaconState, MainnetEthSpec};

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

pub fn process_attestation(ssz_bytes: &[u8], post: &[u8]) -> Vec<u8> {
    //let out: Vec<u8> = Vec::with_capacity(post.len());
    let mut out: Vec<u8> = vec![0 as u8; post.len()];

    println!("{:?}", ssz_bytes.as_ptr());
    println!("{:?}", ssz_bytes.len());
    println!("{:?}", out.as_ptr());
    println!("{:?}", post.len());

    let mut inn: Vec<u8> = ssz_bytes.into();
    let input_ptr: *mut u8 = inn.as_mut_ptr();
    let input_size: usize = ssz_bytes.len() as usize;
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
