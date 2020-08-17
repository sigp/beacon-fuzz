use std::env;

fn main() {
    let prysm_dir = env::var("CARGO_PRYSM_DIR").expect("PRYSM build: CARGO_PRYSM_DIR not defined");
    // Build Prysm beaconfuzz_v2 library
    // go build -o libpfuzz.a -buildmode=c-archive pfuzz.go
    // Prysm deps

    println!("cargo:rustc-link-search=native={}/pfuzz", prysm_dir);
    println!("cargo:rustc-link-lib=static=pfuzz");
    // deps patrick local
    //println!("cargo:rustc-link-search=native={}/src/github.com/herumi/bls-eth-go-binary/bls/lib/linux/amd64", prysm_dir);
    println!("cargo:rustc-link-search=native={}/pfuzz", prysm_dir);
    println!("cargo:rustc-link-lib=static=bls384_256");
    println!("cargo:rustc-link-lib=dylib=stdc++");
}
