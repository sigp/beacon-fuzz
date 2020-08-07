#[link(name = "pfuzz", kind = "static")]
extern "C" {
    fn pfuzz_proposer_slashing(
        beacon_ptr: *mut u8,
        beacon_size: usize,
        attest_ptr: *mut u8,
        attest_size: usize,
        out_ptr: *mut u8,
        out_size: usize,
    ) -> bool;

}

pub fn process_proposer_slashing(
    beacon: &[u8],
    container: &[u8],
    post: &[u8],
    debug: bool,
) -> bool {
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
        pfuzz_proposer_slashing(
            beacon_ptr,
            beacon_size,
            attest_ptr,
            attest_size,
            out_prt,
            out_size,
        )
    };

    if debug {
        use std::fs::File;
        use std::io::Write;
        let mut file_post = File::create("debug_post.ssz").expect("Cannot open debug_post file");
        file_post
            .write(&post)
            .expect("Cannot write debug_post file");
        let mut file_out = File::create("debug_out.ssz").expect("Cannot open debug_out file");
        file_out.write(&out).expect("Cannot write debug_out file");
    }

    // If error triggered during processing, we return immediately
    if !res {
        return res;
    }

    // Verify prysm's post is equal to lighthouse's post
    if out != post {
        panic!("[PRYSM] Mismatch post");
    }
    res
}
