#[link(name = "pfuzz", kind = "static")]
extern "C" {
    fn pfuzz_block_header(
        beacon_ptr: *mut u8,
        beacon_size: usize,
        attest_ptr: *mut u8,
        attest_size: usize,
        out_ptr: *mut u8,
        out_size: usize,
    ) -> bool;
    fn pfuzz_ssz_block_header(input_ptr: *mut u8, input_size: usize) -> bool;
}

use crate::debug::dump_post_state;

pub fn ssz_block_header(input: &[u8]) -> bool {
    let mut inp: Vec<u8> = input.into();
    let input_ptr: *mut u8 = inp.as_mut_ptr();
    let input_size: usize = input.len() as usize;

    let res = unsafe { pfuzz_ssz_block_header(input_ptr, input_size) };
    res
}

pub fn process_block_header(beacon: &[u8], container: &[u8], post: &[u8], debug: bool) -> bool {
    let mut out: Vec<u8> = vec![0 as u8; post.len()];
    let mut b: Vec<u8> = beacon.into();
    let beacon_ptr: *mut u8 = b.as_mut_ptr();
    let beacon_size: usize = beacon.len() as usize;
    let mut c: Vec<u8> = container.into();
    let attest_ptr: *mut u8 = c.as_mut_ptr();
    let attest_size: usize = container.len() as usize;
    let out_prt: *mut u8 = out.as_mut_ptr();
    let out_size = post.len();

    let res = unsafe {
        pfuzz_block_header(
            beacon_ptr,
            beacon_size,
            attest_ptr,
            attest_size,
            out_prt,
            out_size,
        )
    };

    // dump post files for debugging
    if debug {
        dump_post_state(&post, &out);
    }

    // If error triggered during processing, we return immediately
    if !res {
        return res;
    }

    // Verify prysm's post is equal to lighthouse's post
    assert!(out == post, "[PRYSM] Mismatch post");
    res
}
