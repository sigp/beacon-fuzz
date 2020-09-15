use bindgen;

use std::env;
use std::path::PathBuf;

fn main() {
    // TODO does it matter where I put these?
    println!("cargo:rerun-if-changed=src/hello.c");
    println!("cargo:rerun-if-changed=src/hello.h");

    cc::Build::new()
        .file("src/hello.c")
        .include("src")
        .compile("hello");

    let bindings = bindgen::Builder::default()
        .header("src/hello.h")
        .parse_callbacks(Box::new(bindgen::CargoCallbacks))
        .generate()
        .expect("Unable to generate bindings");

    // Write the bindings to the $OUT_DIR/bindings.rs file.
    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");
}
