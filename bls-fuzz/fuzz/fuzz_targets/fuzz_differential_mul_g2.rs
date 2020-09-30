#![no_main]
use libfuzzer_sys::fuzz_target;

use core::ops::Mul;

use bls_fuzz::{milagro_helpers, blst_helpers};
use amcl::bls381::bls381::utils::secret_key_from_bytes;
use blst::min_pk::{Signature as BlstSignature, SecretKey as BlstSecretKey};
use bls12_381::{G2Affine, G2Projective, Scalar};


// Tests [b]*a = c for all implementations against milagro bls
// b is a scalar and a, c are G2 curve points.
fuzz_target!(|data: &[u8]| {
    if data.len() != 128 { return; }
    let a = &data[0..96];
    let b = &data[96..];

    if let Ok(milagro_a) = milagro_helpers::decompress_g2(a) {
        if let Ok(milagro_b) = secret_key_from_bytes(b) {
            // Milagro
            let milagro_c = milagro_a.mul(&milagro_b);
            let c_bytes = milagro_helpers::compress_g2(&milagro_c).to_vec();

            // BLST
            let blst_a = BlstSignature::uncompress(a).unwrap();
            let blst_b = BlstSecretKey::deserialize(b).unwrap();
            let blst_c = blst_helpers::mul_scalar_g2(&blst_a, &blst_b);
            assert_eq!(c_bytes, blst_c.compress().to_vec());

            // ZK-crypto
            let mut data_array = [0u8; 96];
            data_array.copy_from_slice(a);
            let zkcrypto_a: G2Projective = G2Affine::from_compressed_unchecked(&data_array).unwrap().into();
            let mut data_array = [0u8; 32];
            data_array.copy_from_slice(b);
            data_array.reverse(); // ZK-Crypto scalars are little endian
            let zkcrypto_b = Scalar::from_bytes(&data_array).unwrap();
            let zkcrypto_c: G2Affine = zkcrypto_a.mul(&zkcrypto_b).into();
            assert_eq!(c_bytes, zkcrypto_c.to_compressed().to_vec());
        }
    }
});
