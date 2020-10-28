use bfuzz_jni;
use lazy_static::lazy_static;
use regex::Regex;
use std::convert::TryInto;
use std::env;
use std::ffi::CString;
use std::format;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;

use crate::debug::dump_post_state;

const FUZZ_CLASS: &str = "tech/pegasys/teku/fuzz/FuzzUtil";

macro_rules! FUZZ_CLASS_PATH_STRING {
    ($version:tt) => {
        format!("fuzz/build/libs/teku-fuzz-{}.jar", $version)
    };
}

// All supported teku fuzzing targets
pub enum FuzzTarget {
    Attestation,
    AttesterSlashing,
    Block,
    BlockHeader,
    Deposit,
    ProposerSlashing,
    Shuffle,
    VoluntaryExit,
}

impl FuzzTarget {
    fn to_method_name(&self) -> &str {
        match self {
            Self::Attestation => "fuzzAttestation",
            Self::AttesterSlashing => "fuzzAttesterSlashing",
            Self::Block => "fuzzBlock",
            Self::BlockHeader => "fuzzBlockHeader",
            Self::Deposit => "fuzzDeposit",
            Self::ProposerSlashing => "fuzzProposerSlashing",
            Self::Shuffle => "fuzzShuffle",
            Self::VoluntaryExit => "fuzzVoluntaryExit",
        }
    }
}

// Extracts suitable Java CLASS_PATH from teku shell script
// requires teku to have already been built and locally "installed"
fn extract_classpath<P: AsRef<Path>>(teku_root: P) -> String {
    let teku_root_p = teku_root.as_ref();
    let teku_script = teku_root_p.join("build/scripts/teku");
    if !teku_script.is_file() {
        panic!(
            "BeaconFuzz fatal: File does not exist: '{:?}'. Have you built teku?",
            teku_script
        )
    }
    let teku_home = teku_root_p
        .join("build/install/teku")
        .canonicalize()
        .unwrap();
    if !teku_home.is_dir() {
        panic!(
            "BeaconFuzz fatal: Directory does not exist '{:?}'. Have you built teku?",
            teku_home
        )
    }
    // TODO replace with rust equivalent
    // JAVA_CLASSPATH=$(grep -F CLASSPATH= "$TEKU_SCRIPT" | head -n 1 | cut -d= -f 2 | sed 's:\$APP_HOME:'"$TEKU_HOME"':g')
    let output = Command::new("sh")
        .arg("-c")
        .arg(format!(
            "grep -F CLASSPATH= \"{}\" | head -n 1 | cut -d= -f 2 | sed 's:\\$APP_HOME:'\"{}\"':g'",
            teku_script.display(),
            teku_home.display()
        ))
        .output()
        .expect("BeaconFuzz failed to execute command to extract Teku CLASSPATH");
    if !output.status.success() {
        panic!("BeaconFuzz fatal: Failed to extract Teku CLASSPATH() from script");
    }
    let dist_classpath = String::from_utf8(output.stdout).unwrap();
    let version = teku_version_from_classpath(&dist_classpath)
        .expect("BeaconFuzz fatal: unable to extract teku version from distribution classpath.");
    let teku_fuzz_jar = teku_root_p.join(FUZZ_CLASS_PATH_STRING!(version)).canonicalize().expect("BeaconFuzz fatal: unable to locate teku fuzz class. Did you build with ./gradlew fuzz:build?");
    format!("{}:{}", dist_classpath, teku_fuzz_jar.display())
}

// Gets the current teku version
// Alternative, but requires the compiled classpath version to be equiv to the current source code,
// which might not always be true
/*fn get_current_version<P: AsRef<Path>>(teku_root: P) -> String {
    let output = Command::new("sh")
        .arg("-c")
        .arg(
            "./gradlew properties | grep version: | cut -d' ' -f 2"
        )
        .current_dir(teku_root)
        .output()
        .expect("BeaconFuzz failed to execute command to extract Teku version");
    if !output.status.success() {
        panic!("BeaconFuzz fatal: Failed to extract Teku CLASSPATH() from script");
    }
    output
}*/

//
fn teku_version_from_classpath(teku_classpath: &str) -> Option<&str> {
    lazy_static! {
        static ref RE: Regex =
            Regex::new(r"teku-[^/:]*?(?P<ver>\d+(?:\.\d+)*(?:-SNAPSHOT)?)\.jar").unwrap();
    }
    RE.captures(teku_classpath)
        .and_then(|cap| cap.name("ver").map(|ver| ver.as_str()))
}

// TODO safety to ensure this is never called twice
pub fn init_teku(disable_bls: bool, target: FuzzTarget) {
    let teku_root = PathBuf::from(
        env::var("BFUZZ_TEKU_DIR").expect("BeaconFuzz config error: BFUZZ_TEKU_DIR not defined"),
    );
    let class_path = CString::new(extract_classpath(teku_root)).expect("CString::new failed");
    let fuzz_class = CString::new(FUZZ_CLASS).expect("CString::new failed");
    let method_name = CString::new(target.to_method_name()).expect("CString::new failed");

    unsafe {
        bfuzz_jni::bfuzz_jni_init(
            fuzz_class.as_ptr(),
            method_name.as_ptr(),
            class_path.as_ptr(),
            disable_bls,
        );
    }
}

pub fn run_target(input: &[u8], lh_post: &[u8], debug: bool) -> bool {
    // TODO make unsafe chunk smaller
    // only needed around the 2 bfuzz_jni calls and the set_len
    unsafe {
        let ret = bfuzz_jni::bfuzz_jni_run(input.as_ptr(), input.len().try_into().unwrap());
        //if debug {
        //    println!("bfuzz_jni_run result val: {:?}", ret);
        //}
        // If error triggered during processing, we return immediately
        if ret < 0 {
            return false;
        }

        let mut result: Vec<u8> = Vec::with_capacity(ret.try_into().unwrap());
        let result_size: usize = ret.try_into().unwrap();
        // NOTE: the C code uses a size_t but bindgen uses a u64 instead of usize
        // (though looks to be more accurate behaviour)
        // https://github.com/rust-lang/rust-bindgen/issues/1671
        bfuzz_jni::bfuzz_jni_load_result(result.as_mut_ptr(), result_size.try_into().unwrap());
        result.set_len(result_size);
        //if debug {
        //    println!("result content: {:?}", result);
        //}
        if result.as_slice() != lh_post {
            if debug {
                println!("[TEKU] Mismatch post");
            } else {
                // make fuzzer to crash
                panic!("[TEKU] Mismatch post");
            }
        }

        // dump post files for debugging
        if debug {
            dump_post_state(&lh_post, result.as_slice());
        }
    }

    true
}

/*
fn main() {
    init_teku(true, FuzzTarget::Attestation);
    // NOTE: this raises an exception because we expect to have received valid SSZ after initial
    // pre-processing
    let data: Vec<u8> = vec![0; 50];
    let post: Vec<u8> = vec![0; 50];
    run_target(data.as_slice(), post.as_slice(), true);
}
*/

// TODO(gnattishness) use for unit test
/*fn main() {
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
}*/

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_teku_version_from_classpath_finds_result() {
        let input = "$APP_HOME/lib/teku-0.12.9-SNAPSHOT.jar:$APP_HOME/lib/teku-0.12.9-SNAPSHOT.jar:$APP_HOME/lib/teku-services-beaconchain-0.12.9-SNAPSHOT.jar";
        assert_eq!(teku_version_from_classpath(input), Some("0.12.9-SNAPSHOT"));
        let input2 = "$APP_HOME/lib/teku-services-beaconchain-0.13.8-SNAPSHOT.jar";
        assert_eq!(teku_version_from_classpath(input2), Some("0.13.8-SNAPSHOT"));
    }

    #[test]
    fn test_teku_version_from_classpath_weird_versions() {
        let input = "$APP_HOME/lib/teku-0.12.9.jar";
        assert_eq!(teku_version_from_classpath(input), Some("0.12.9"));
        let input2 = "$APP_HOME/lib/teku-0.12-SNAPSHOT.jar";
        assert_eq!(teku_version_from_classpath(input2), Some("0.12-SNAPSHOT"));
        let input3 = "$APP_HOME/lib/teku-1.jar";
        assert_eq!(teku_version_from_classpath(input3), Some("1"));
    }

    #[test]
    fn test_teku_version_from_classpath_none_when_missing() {
        let input = "$APP_HOME/lib/";
        assert!(teku_version_from_classpath(input).is_none());
        let input2 = "";
        assert!(teku_version_from_classpath(input2).is_none());
        let input3= "$APP_HOME/lib/j2objc-annotations-0.15.8-SNAPSHOT.jar:$APP_HOME/lib/jackson-core-0.12.9-SNAPSHOT.jar";
        assert!(teku_version_from_classpath(input3).is_none());
        let input4 = "$APP_HOME/lib/teku/j2objc-annotations-0.15.8-SNAPSHOT.jar";
        assert!(teku_version_from_classpath(input4).is_none());
        let input5 = "$APP_HOME/lib/teku/*:$APP_HOME/lib/jackson-core-0.12.9-SNAPSHOT.jar";
        assert!(teku_version_from_classpath(input5).is_none());
    }

    #[test]
    fn test_teku_version_from_classpath_avoids_non_teku() {
        let input = "$APP_HOME/lib/j2objc-annotations-0.15.8-SNAPSHOT.jar:$APP_HOME/lib/teku-0.12.9-SNAPSHOT.jar:$APP_HOME/lib/teku-services-beaconchain-0.12.9-SNAPSHOT.jar";
        assert_eq!(teku_version_from_classpath(input), Some("0.12.9-SNAPSHOT"));
    }
}
