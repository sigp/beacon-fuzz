#![no_main]
use libfuzzer_sys::fuzz_target;
use milagro_bls::PublicKey;

fuzz_target!(|data: &[u8]| {
    if let Ok(pk) = PublicKey::from_bytes(data) {
        let data_round_trip = pk.as_bytes();
        assert_eq!(data.to_vec(), data_round_trip.to_vec());
    }
});
