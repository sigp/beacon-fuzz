#![no_main]
use libfuzzer_sys::fuzz_target;
use blst::min_sig::Signature;

fuzz_target!(|data: &[u8]| {
    if let Ok(sig) = Signature::uncompress(data) {
        let data_round_trip = sig.compress();
        assert_eq!(data.to_vec(), data_round_trip.to_vec());
    }
});
