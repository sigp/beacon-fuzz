#![no_main]
use libfuzzer_sys::fuzz_target;
use milagro_bls::{AggregateSignature as MilagroAggregateSignature, Signature as MilagroSignature};
use blst::min_pk::{AggregateSignature as BlstAggregateSignature, Signature as BlstSignature};
use bls12_381::{G2Affine, G2Projective};
use core::ops::Add;

// Tests a + b = c (a,b,c are on G2) for all implementations against milagro bls
fuzz_target!(|data: &[u8]| {
    if data.len() != 192 { return; }
    let a = &data[0..96];
    let b = &data[96..];

    if let Ok(milagro_a) = MilagroSignature::from_bytes(a) {
        if let Ok(milagro_b) = MilagroSignature::from_bytes(b) {
            // Milagro
            let mut milagro_c = MilagroAggregateSignature::from_signature(&milagro_a);
            milagro_c.add(&milagro_b);
            let c_bytes = milagro_c.as_bytes().to_vec();

            // BLST
            let mut blst_a = BlstAggregateSignature::from_signature(&BlstSignature::uncompress(a).unwrap());
            let blst_b = BlstSignature::uncompress(b).unwrap();
            blst_a.add_signature(&blst_b);
            assert_eq!(c_bytes, BlstSignature::from_aggregate(&blst_a).compress().to_vec());


            // ZK-crypto
            let mut data_array = [0u8; 96];
            data_array.copy_from_slice(a);
            let zkcrypto_a: G2Projective = G2Affine::from_compressed_unchecked(&data_array).unwrap().into();
            data_array.copy_from_slice(b);
            let zkcrypto_b: G2Projective = G2Affine::from_compressed_unchecked(&data_array).unwrap().into();
            let zkcrypto_c: G2Affine = zkcrypto_a.add(&zkcrypto_b).into();
            assert_eq!(c_bytes, zkcrypto_c.to_compressed().to_vec());
        }
    }
});
