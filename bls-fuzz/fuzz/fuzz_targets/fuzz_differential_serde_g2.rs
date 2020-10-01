#![no_main]
use libfuzzer_sys::fuzz_target;
use milagro_bls::Signature as MilagroSignature;
use blst::min_pk::Signature as BlstSignature;
use bls12_381::G2Affine;

fuzz_target!(|data: &[u8]| {
    // BLST
    let blst_g2 = BlstSignature::uncompress(data);
    let blst_error = blst_g2.is_err();
    let mut blst_round_trip = data.to_vec();
    if let Ok(g2) = blst_g2 {
        blst_round_trip = g2.compress().to_vec();
    }

    // Milagro
    let mut milagro_round_trip = data.to_vec();
    let milagro_g2 = MilagroSignature::from_bytes(data);
    let milagro_error = milagro_g2.is_err();
    if let Ok(g2) = milagro_g2 {
        milagro_round_trip = g2.as_bytes().to_vec();

        // ZK-crypto
        // TODO: ZK-crypto does not validate point is on the curve so we can only test it on valid bytes.
        let mut data_array = [0u8; 96];
        data_array.copy_from_slice(data);
        let zkcrypto_g2 = G2Affine::from_compressed_unchecked(&data_array).unwrap();
        assert_eq!(milagro_round_trip, zkcrypto_g2.to_compressed().to_vec());
    }

    assert_eq!(milagro_error, blst_error);
    assert_eq!(milagro_round_trip, blst_round_trip);
});
