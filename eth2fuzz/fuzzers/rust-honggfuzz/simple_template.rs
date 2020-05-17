#[macro_use] extern crate honggfuzz;
extern crate fuzz_targets;
use fuzz_targets::fuzz_###TARGET### as fuzz_target;

fn main() {
    loop {
        fuzz!(|data|{
            fuzz_target(data);
        })
    }
}
