pub const SCALAR_BYTES: usize = 32;
pub const G1_BYTES: usize = 48;
pub const G2_BYTES: usize = 96;
pub const P_HEX: &str = "1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab";
pub const Q_HEX: &str = "73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001";

// This file provides wrapper functions where required for BLS libraries.
pub mod milagro_helpers {
    use super::*;

    use amcl::bls381::bls381::utils::{deserialize_g1, deserialize_g2, serialize_g1, serialize_g2};
    use amcl::bls381::ecp::ECP;
    use amcl::bls381::ecp2::ECP2;
    use amcl::errors::AmclError;

    pub fn decompress_g1(g1_bytes: &[u8]) -> Result<ECP, AmclError> {
        if g1_bytes.len() != G1_BYTES {
            return Err(AmclError::InvalidG1Size);
        }
        deserialize_g1(g1_bytes)
    }

    pub fn compress_g1(g1: &ECP) -> [u8; G1_BYTES] {
        serialize_g1(g1)
    }

    pub fn decompress_g2(g2_bytes: &[u8]) -> Result<ECP2, AmclError> {
        if g2_bytes.len() != G2_BYTES {
            return Err(AmclError::InvalidG1Size);
        }
        deserialize_g2(g2_bytes)
    }

    pub fn compress_g2(g2: &ECP2) -> [u8; G2_BYTES] {
        serialize_g2(g2)
    }
}

pub mod blst_helpers {
    use blst::min_pk::*;
    use blst::*;

    pub fn mul_scalar_g1(point: &PublicKey, scalar: &SecretKey) -> PublicKey {
        let mut out = PublicKey::default();
        let mut t1 = blst_p1::default();
        unsafe {
            blst_p1_from_affine(&mut t1, &point.point);
            let mut t2 = blst_p1::default();
            blst::blst_p1_mult(&mut t2, &t1, &scalar.value, 255);
            blst_p1_to_affine(&mut out.point, &t2);
        }
        out
    }

    pub fn mul_scalar_g2(point: &Signature, scalar: &SecretKey) -> Signature {
        let mut out = Signature::default();
        let mut t1 = blst_p2::default();
        unsafe {
            blst_p2_from_affine(&mut t1, &point.point);
            let mut t2 = blst_p2::default();
            blst::blst_p2_mult(&mut t2, &t1, &scalar.value, 255);
            blst_p2_to_affine(&mut out.point, &t2);
        }
        out
    }
}
