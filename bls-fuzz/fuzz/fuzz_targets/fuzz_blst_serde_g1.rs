#![no_main]
use libfuzzer_sys::fuzz_target;
use blst::min_pk::PublicKey;

fuzz_target!(|data: &[u8]| {
    if let Ok(pk) = PublicKey::uncompress(data) {
        let data_round_trip = pk.compress();
        assert_eq!(data.to_vec(), data_round_trip.to_vec());
    }
});
