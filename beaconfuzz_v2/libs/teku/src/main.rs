use bfuzz_jni;

fn main() {
    unsafe {
        bfuzz_jni::hello();
    }
}
