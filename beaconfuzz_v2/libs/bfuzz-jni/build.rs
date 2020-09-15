fn main() {
    cc::Build::new().file("src/hello.c").compile("hello");
    println!("cargo:rerun-if-changed=src/hello.c");
}
