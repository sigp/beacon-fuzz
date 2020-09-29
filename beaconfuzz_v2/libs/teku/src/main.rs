use bfuzz_jni;
use std::convert::TryInto;
use std::env;
use std::ffi::CString;
// TODO(gnattishness) not sure why import is needed here?

fn main() {
    // dummy to try calling the java
    let class_name = CString::new("DummyFuzzUtil").expect("CString::new failed");
    let method_name = CString::new("fuzzAttestation").expect("CString::new failed");
    // lol at this rust code
    //let class_path = CString::new(
    //    env::current_dir()
    //        .unwrap()
    //        .canonicalize()
    //        .unwrap()
    //        .to_str()
    //        .unwrap(),
    //)
    //.expect("CString::new failed");
    let class_path = CString::new(
        env::current_dir()
            .unwrap()
            .join("../bfuzz-jni/src")
            .canonicalize()
            .unwrap()
            .to_str()
            .unwrap(),
    )
    .expect("CString::new failed");
    let bls_disabled = true;
    let mut data: Vec<u8> = vec![0; 50];
    for i in 1..=5 {
        data[i - 1] = i as u8;
    }
    // data is 1,2,3,4,5,0,0,0,0...
    unsafe {
        bfuzz_jni::bfuzz_jni_init(
            class_name.as_ptr(),
            method_name.as_ptr(),
            class_path.as_ptr(),
            bls_disabled,
        );
        let ret = bfuzz_jni::bfuzz_jni_run(data.as_ptr(), data.len().try_into().unwrap());
        println!("bfuzz_jni_run result val: {:?}", ret);
        if ret >= 0 {
            let mut result: Vec<u8> = Vec::with_capacity(ret.try_into().unwrap());
            let result_size: usize = ret.try_into().unwrap();
            // NOTE: the C code uses a size_t but bindgen uses a u64 instead of usize
            // (though looks to be more accurate behaviour)
            // https://github.com/rust-lang/rust-bindgen/issues/1671
            bfuzz_jni::bfuzz_jni_load_result(result.as_mut_ptr(), result_size.try_into().unwrap());
            result.set_len(result_size);
            println!("result content: {:?}", result);
        }
    }
}
