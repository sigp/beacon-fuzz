fn main() {
    println!("cargo:rustc-link-search=native=../../nim-beacon-chain/build");
    println!("cargo:rustc-link-lib=static=nfuzz");
    println!("cargo:rustc-link-search=native=../../nim-beacon-chain/vendor/nim-libbacktrace/install/usr/lib");
    println!("cargo:rustc-link-lib=static=backtracenim");
    println!("cargo:rustc-link-lib=static=backtrace");
    //println!("cargo:rustc-link-lib=static=pcre");
}
