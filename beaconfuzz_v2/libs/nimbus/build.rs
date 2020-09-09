use std::env;

fn main() {
    let nimbus_dir =
        env::var("CARGO_NIMBUS_DIR").expect("NIMBUS build: CARGO_NIMBUS_DIR not defined");

    println!("cargo:rustc-link-search=native={}/build", nimbus_dir);
    println!("cargo:rustc-link-lib=static=nfuzz");
    println!(
        "cargo:rustc-link-search=native={}/vendor/nim-libbacktrace/install/usr/lib",
        nimbus_dir
    );
    println!("cargo:rustc-link-lib=static=backtracenim");
    println!("cargo:rustc-link-lib=static=backtrace");
    println!("cargo:rustc-link-lib=dylib=pcre");
}
