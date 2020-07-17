fn main() {
    // Nimbus deps
    println!("cargo:rustc-link-search=native=../../nim-beacon-chain/build");
    println!("cargo:rustc-link-lib=static=nfuzz");
    println!("cargo:rustc-link-search=native=../../nim-beacon-chain/vendor/nim-libbacktrace/install/usr/lib");
    println!("cargo:rustc-link-lib=static=backtracenim");
    println!("cargo:rustc-link-lib=static=backtrace");
    println!("cargo:rustc-link-lib=static=pcre");
    // Build Prysm beaconfuzz_v2 library
    // go build -o libpfuzz.a -buildmode=c-archive pfuzz.go
    // Prysm deps
    println!("cargo:rustc-link-search=native=./libs/pfuzz");
    println!("cargo:rustc-link-lib=static=pfuzz");
    // deps patrick local
    println!("cargo:rustc-link-search=native=../../prysm/src/github.com/herumi/bls-eth-go-binary/bls/lib/linux/amd64");
    println!("cargo:rustc-link-lib=static=bls384_256");
    println!("cargo:rustc-link-lib=dylib=stdc++");
}
