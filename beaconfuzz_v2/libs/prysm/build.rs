fn main() {
    // Build Prysm beaconfuzz_v2 library
    // go build -o libpfuzz.a -buildmode=c-archive pfuzz.go
    // Prysm deps
    println!("cargo:rustc-link-search=native=../../prysm/pfuzz");
    println!("cargo:rustc-link-lib=static=pfuzz");
    // deps patrick local
    println!("cargo:rustc-link-search=native=../../prysm/src/github.com/herumi/bls-eth-go-binary/bls/lib/linux/amd64");
    println!("cargo:rustc-link-lib=static=bls384_256");
    println!("cargo:rustc-link-lib=dylib=stdc++");
}
