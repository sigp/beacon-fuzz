use types::{BeaconState, MainnetEthSpec};

#[link(name = "nfuzz")]
extern "C" {
    fn NimMain();
    fn nfuzz_attestation(
        input_ptr: *const u8,
        input_size: usize,
        output_ptr: *const u8,
        output_size: usize,
        disable_bls: bool,
    ) -> bool;
}

pub fn process_attestation(ssz_bytes: &[u8], post: &[u8]) {
    //let out: Vec<u8> = Vec::with_capacity(post.len());
    let out: Vec<u8> = vec![0 as u8; post.len()];

    println!("{:?}", ssz_bytes.as_ptr());
    println!("{:?}", ssz_bytes.len());
    println!("{:?}", out.as_ptr());
    println!("{:?}", post.len());

    let res = unsafe {
        // initialize nim gc memory, types and stack
        NimMain();

        nfuzz_attestation(
            ssz_bytes.as_ptr(),
            ssz_bytes.len(),
            out.as_ptr(),
            post.len(),
            false,
        )
    };
    //println!("Nim fib(20) is: {}", res);
    println!("result: {}", res);

    assert_eq!(out, post);
}
