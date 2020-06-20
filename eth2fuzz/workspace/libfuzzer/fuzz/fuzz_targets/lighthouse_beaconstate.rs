#![no_main]
extern crate libfuzzer_sys;
use libfuzzer_sys::fuzz_target;

extern crate fuzz_targets;
use fuzz_targets::fuzz_lighthouse_beaconstate as fuzz_target;

fuzz_target!(|data: &[u8]| {
    fuzz_target(data);
});
