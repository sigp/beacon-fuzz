#![no_main]
use libfuzzer_sys::fuzz_target;
use milagro_bls::PublicKey as MilagroPublicKey;
use blst::min_pk::PublicKey as BlstPublicKey;
use bls12_381::G1Affine;

fuzz_target!(|data: &[u8]| {
    // TODO: Known BLST Issue (0, +-2) is counted as infinity
    if data.len() > 0 && (data[0] == 128 || data[0] == 160) { return; }

    // BLST
    let blst_g1 = BlstPublicKey::uncompress(data);
    let blst_error = blst_g1.is_err();
    let mut blst_round_trip = data.to_vec();
    if let Ok(g1) = blst_g1 {
        blst_round_trip = g1.compress().to_vec();
    }

    // Milagro
    let mut milagro_round_trip = data.to_vec();
    let milagro_g1 = MilagroPublicKey::from_bytes(data);
    let milagro_error = milagro_g1.is_err();
    if let Ok(g1) = milagro_g1 {
        milagro_round_trip = g1.as_bytes().to_vec();

        // ZK-crypto
        // TODO: ZK-crypto does not validate point is on the curve so we can only test it on valid bytes.
        let mut data_array = [0u8; 48];
        data_array.copy_from_slice(data);
        let zkcrypto_g1 = G1Affine::from_compressed_unchecked(&data_array).unwrap();
        assert_eq!(milagro_round_trip, zkcrypto_g1.to_compressed().to_vec());
    }

    assert_eq!(milagro_error, blst_error);
    assert_eq!(milagro_round_trip, blst_round_trip);
});
