use structopt::StructOpt;

use crate::targets::Targets;

#[derive(Fail, Debug)]
#[fail(display = "[eth2fuzz] Fuzzer quit")]
pub struct FuzzerQuit;

arg_enum! {
    #[derive(StructOpt, Debug, Clone, Copy, PartialEq, Eq)]
    /// All the fuzzers currently available
    pub enum Fuzzer {
        // Rust fuzzers
        Afl,
        Honggfuzz,
        Libfuzzer,
        // Javascript fuzzers
        Jsfuzz,
        // Nim fuzzers
        //NimAfl,
        NimLibfuzzer,
        // Go fuzzers
        GoLibfuzzer,
        // java fuzzer
        JavaJQFAfl
    }
}

pub fn get_default_fuzzer(target: Targets) -> Fuzzer {
    match target.language().as_str() {
        "rust" => Fuzzer::Honggfuzz,
        "js" => Fuzzer::Jsfuzz,
        "nim" => Fuzzer::NimLibfuzzer,
        "go" => Fuzzer::GoLibfuzzer,
        "java" => Fuzzer::JavaJQFAfl,
        _ => panic!("default fuzzer not yet supported"),
    }
}

arg_enum! {
    /// All the Sanitizers currently available
    ///
    /// NOTES: https://doc.rust-lang.org/nightly/unstable-book/compiler-flags/sanitizer.html
    #[derive(StructOpt, Debug, Clone, Copy, PartialEq, Eq)]
    pub enum Sanitizer {
        Address,
        Leak,
        Memory,
        Thread,
    }
}

impl Sanitizer {
    /// Sanitizer names used for RUSTFLAGS env variable.
    pub fn name(&self) -> String {
        match &self {
            Sanitizer::Address => "address".to_string(),
            Sanitizer::Leak => "leak".to_string(),
            Sanitizer::Memory => "memory".to_string(),
            Sanitizer::Thread => "thread".to_string(),
        }
    }
}

/// Configuration structure common for all fuzzers
#[derive(Debug, Default, Clone, Copy)]
pub struct FuzzerConfig {
    // Fuzzer timeout
    pub timeout: Option<i32>,
    // Number of fuzzing thread
    pub thread: Option<i32>,
    // Sanitizer
    pub sanitizer: Option<Sanitizer>,
    // Seed
    pub seed: Option<i32>,
}
