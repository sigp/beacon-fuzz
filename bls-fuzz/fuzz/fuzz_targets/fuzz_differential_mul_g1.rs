#![no_main]
use libfuzzer_sys::fuzz_target;

use core::ops::Mul;

use bls_fuzz::{milagro_helpers, blst_helpers};
use amcl::bls381::bls381::utils::secret_key_from_bytes;
use blst::min_pk::{PublicKey as BlstPublicKey, SecretKey as BlstSecretKey};
use bls12_381::{G1Affine, G1Projective, Scalar};


// Tests [b]*a = c for all implementations against milagro bls
// b is a scalar and a, c are G1 curve points.
fuzz_target!(|data: &[u8]| {
    if data.len() != 80 { return; }
    let a = &data[0..48];
    let b = &data[48..];

    // Known BLST Issue (0, +-2) is counted as infinity
    if a[0] == 128 || a[0] == 160 || b[0] == 128 || b[0] == 160 { return; }


    if let Ok(milagro_a) = milagro_helpers::decompress_g1(a) {
        if let Ok(milagro_b) = secret_key_from_bytes(b) {
            // Milagro
            let milagro_c = milagro_a.mul(&milagro_b);
            let c_bytes = milagro_helpers::compress_g1(&milagro_c).to_vec();

            // BLST
            let blst_a = BlstPublicKey::uncompress(a).unwrap();
            let blst_b = BlstSecretKey::deserialize(b).unwrap();
            let blst_c = blst_helpers::mul_scalar_g1(&blst_a, &blst_b);
            assert_eq!(c_bytes, blst_c.compress().to_vec());

            // ZK-crypto
            let mut data_array = [0u8; 48];
            data_array.copy_from_slice(a);
            let zkcrypto_a: G1Projective = G1Affine::from_compressed_unchecked(&data_array).unwrap().into();
            let mut data_array = [0u8; 32];
            data_array.copy_from_slice(b);
            data_array.reverse(); // ZK-Crypto scalars are little endian
            let zkcrypto_b = Scalar::from_bytes(&data_array).unwrap();
            let zkcrypto_c: G1Affine = zkcrypto_a.mul(&zkcrypto_b).into();
            assert_eq!(c_bytes, zkcrypto_c.to_compressed().to_vec());
        }
    }
});
