#[macro_use] extern crate afl;
extern crate fuzz_targets;
use fuzz_targets::fuzz_lighthouse_enr as fuzz_target;

fn main() {
    fuzz!(|data|{
        fuzz_target(data);
    });
}
