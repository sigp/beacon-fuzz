#[link(name = "pfuzz", kind = "static")]
extern "C" {
    fn PrysmMain(bls: bool);
    fn pfuzz_block_header(
        beacon_ptr: *mut u8,
        beacon_size: usize,
        attest_ptr: *mut u8,
        attest_size: usize,
        out_ptr: *mut u8,
        out_size: usize,
    ) -> bool;

}

pub fn process_block_header(beacon: &[u8], attest: &[u8], post: &[u8]) -> bool {
    let mut out: Vec<u8> = vec![0 as u8; post.len()];
    let mut inn: Vec<u8> = beacon.into();
    let beacon_ptr: *mut u8 = inn.as_mut_ptr();
    let beacon_size: usize = beacon.len() as usize;
    let mut inn: Vec<u8> = attest.into();
    let attest_ptr: *mut u8 = inn.as_mut_ptr();
    let attest_size: usize = attest.len() as usize;
    let out_prt: *mut u8 = out.as_mut_ptr();
    let out_size = post.len();

    let res = unsafe {
        //PrysmMain(false);
        pfuzz_block_header(
            beacon_ptr,
            beacon_size,
            attest_ptr,
            attest_size,
            out_prt,
            out_size,
        )
    };

    assert_eq!(out, post);
    println!("[PRYSM]: {}", res);
    res
}
