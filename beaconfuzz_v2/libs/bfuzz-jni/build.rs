use bindgen;

use std::env;
use std::path::PathBuf;

fn main() {
    // TODO does it matter where I put these?
    // TODO use clang?
    println!("cargo:rerun-if-changed=src/bfuzzjni.c");
    println!("cargo:rerun-if-changed=src/bfuzzjni.h");

    let jvm_home = PathBuf::from(env::var("JAVA_HOME").expect("JAVA_HOME not set"));
    println!("cargo:rustc-link-search={}", jvm_home.join("lib").display());
    println!(
        "cargo:rustc-link-search={}",
        jvm_home.join("lib/server").display()
    );
    println!("cargo:rustc-link-lib=jvm");
    // TODO need the equiv of -Wl,-R"${JAVA_HOME}/lib/server"?
    // NOTE assumes a linux system here.
    cc::Build::new()
        .file("src/bfuzzjni.c")
        .include("src")
        .include(jvm_home.join("include"))
        .include(jvm_home.join("include/linux"))
        .compile("bfuzzjni");

    let bindings = bindgen::Builder::default()
        .header("src/bfuzzjni.h")
        .parse_callbacks(Box::new(bindgen::CargoCallbacks))
        .generate()
        .expect("Unable to generate bindings");

    // Write the bindings to the $OUT_DIR/bindings.rs file.
    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");
}
