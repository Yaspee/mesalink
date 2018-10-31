// Copyright 2015-2016 Brian Smith.
//
// Permission to use, copy, modify, and/or distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
//
// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHORS DISCLAIM ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY
// SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
// OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
// CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

//! ECDSA Signatures using the P-256 and P-384 curves.

use arithmetic::montgomery::*;
use {der, digest, error, private, signature, polyfill};
use super::digest_scalar::digest_scalar;
use ec::suite_b::{ops::*, public_key::*, verify_jacobian_point_is_on_the_curve};
use untrusted;

/// An ECDSA verification algorithm.
pub struct Algorithm {
    ops: &'static PublicScalarOps,
    digest_alg: &'static digest::Algorithm,
    split_rs:
        for<'a> fn(ops: &'static ScalarOps, input: &mut untrusted::Reader<'a>)
                   -> Result<(untrusted::Input<'a>, untrusted::Input<'a>),
                             error::Unspecified>,
    id: AlgorithmID,
}

#[derive(Debug)]
enum AlgorithmID {
    ECDSA_P256_SHA256_ASN1,
    ECDSA_P256_SHA256_FIXED,
    ECDSA_P256_SHA384_ASN1,
    ECDSA_P384_SHA256_ASN1,
    ECDSA_P384_SHA384_ASN1,
    ECDSA_P384_SHA384_FIXED,
    ECDSA_SM2_SM3_ASN1,
    ECDSA_SM2_SM3_FIXED,
    ECDSA_SM2_SHA256_ASN1,
    ECDSA_SM2_SHA256_FIXED
}

derive_debug_from_field!(Algorithm, id);

fn get_sm2_z(ops: &PublicKeyOps, pub_key: (Elem<R>, Elem<R>)) -> digest::Digest {
    let _len: usize = 2 + 14 + 6 * 32;
    let mut s: [u32; 52] = [0; 52];

    // TODO: add ID length two bytes
    s[0] = 0x31323334;
    s[1] = 0x35363738;
    s[2] = 0x31323334;
    s[3] = 0x35363738;

    // a
    s[4] = 0xfffffffe;
    s[5] = 0xffffffff;
    s[6] = 0xffffffff;
    s[7] = 0xffffffff;
    s[8] = 0xffffffff;
    s[9] = 0x00000000;
    s[10] = 0xffffffff;
    s[11] = 0xfffffffc;

    // b
    s[12] = 0x28e9fa9e;
    s[13] = 0x9d9f5e34;
    s[14] = 0x4d5a9e4b;
    s[15] = 0xcf6509a7;
    s[16] = 0xf39789f5;
    s[17] = 0x15ab8f92;
    s[18] = 0xddbcbd41;
    s[19] = 0x4d940e93;

    // G_x
    s[20] = 0x32C4AE2C;
    s[21] = 0x1F198119;
    s[22] = 0x5F990446;
    s[23] = 0x6A39C994;
    s[24] = 0x8FE30BBF;
    s[25] = 0xF2660BE1;
    s[26] = 0x715A4589;
    s[27] = 0x334C74C7;

    // G_y
    s[28] = 0xBC3736A2;
    s[29] = 0xF4F6779C;
    s[30] = 0x59BDCEE3;
    s[31] = 0x6B692153;
    s[32] = 0xD0A9877C;
    s[33] = 0xC62A4740;
    s[34] = 0x02DF32E5;
    s[35] = 0x2139F0A0;

    // q_x and q_y
    let q_x = ops.common.elem_unencoded(&pub_key.0);
    let q_y = ops.common.elem_unencoded(&pub_key.1);

    s[36..44].copy_from_slice(polyfill::slice::u64_as_u32(&q_x.limbs[0..4]));
    s[44..52].copy_from_slice(polyfill::slice::u64_as_u32(&q_y.limbs[0..4]));

    s[36..44].reverse();
    s[44..52].reverse();

    // TODO: fix these ugly code
    let buf1 = polyfill::slice::u32_as_u8(&s);
    let mut buf2 = [0, 0x80].to_vec();
    buf2.extend_from_slice(&buf1);
    digest::digest(&digest::SM3, &buf2[0..210])
}

impl signature::VerificationAlgorithm for Algorithm {
    fn verify(&self, public_key: untrusted::Input, msg: untrusted::Input,
              signature: untrusted::Input) -> Result<(), error::Unspecified> {
        // NSA Suite B Implementer's Guide to ECDSA Section 3.4.2.

        let public_key_ops = self.ops.public_key_ops;
        let scalar_ops = self.ops.scalar_ops;

        let is_sm2 = match self.id {
            AlgorithmID::ECDSA_SM2_SM3_ASN1 |
            AlgorithmID::ECDSA_SM2_SM3_FIXED |
            AlgorithmID::ECDSA_SM2_SHA256_ASN1 |
            AlgorithmID::ECDSA_SM2_SHA256_FIXED => true,
            _ => false,
        };

        // NSA Guide Prerequisites:
        //
        //    Prior to accepting a verified digital signature as valid the
        //    verifier shall have:
        //
        //    1. assurance of the signatory’s claimed identity,
        //    2. an authentic copy of the domain parameters, (q, FR, a, b, SEED,
        //       G, n, h),
        //    3. assurance of the validity of the public key, and
        //    4. assurance that the claimed signatory actually possessed the
        //       private key that was used to generate the digital signature at
        //       the time that the signature was generated.
        //
        // Prerequisites #1 and #4 are outside the scope of what this function
        // can do. Prerequisite #2 is handled implicitly as the domain
        // parameters are hard-coded into the source. Prerequisite #3 is
        // handled by `parse_uncompressed_point`.
        let peer_pub_key = parse_uncompressed_point(public_key_ops, public_key)?;

        let (r, s) = signature.read_all(
            error::Unspecified, |input| (self.split_rs)(scalar_ops, input))?;

        // NSA Guide Step 1: "If r and s are not both integers in the interval
        // [1, n − 1], output INVALID."
        let r = scalar_parse_big_endian_variable(public_key_ops.common,
                                                 AllowZero::No, r)?;
        let s = scalar_parse_big_endian_variable(public_key_ops.common,
                                                 AllowZero::No, s)?;
        let e = {
            // SM2: compute Z
            if is_sm2 {
                let mut z = get_sm2_z(public_key_ops, peer_pub_key).as_ref().to_vec();
                let mut msg = msg.as_slice_less_safe();
                z.extend_from_slice(msg);
            }
            // NSA Guide Step 2: "Use the selected hash function to compute H =
            // Hash(M)."
            // SM2 specific code end
            let h = digest::digest(self.digest_alg, msg.as_slice_less_safe());

            // NSA Guide Step 3: "Convert the bit string H to an integer e as
            // described in Appendix B.2."
            digest_scalar(scalar_ops, &h)
        };

        if !is_sm2 {
            // ECDSA P-256 and P-384

            // NSA Guide Step 4: "Compute w = s**−1 mod n, using the routine in
            // Appendix B.1."
            let w = scalar_ops.scalar_inv_to_mont(&s);

            // NSA Guide Step 5: "Compute u1 = (e * w) mod n, and compute
            // u2 = (r * w) mod n."
            let u1 = scalar_ops.scalar_product(&e, &w);
            let u2 = scalar_ops.scalar_product(&r, &w);

            // NSA Guide Step 6: "Compute the elliptic curve point
            // R = (xR, yR) = u1*G + u2*Q, using EC scalar multiplication and EC
            // addition. If R is equal to the point at infinity, output INVALID."
            let product =
                twin_mul(self.ops.private_key_ops, &u1, &u2, &peer_pub_key);

            // Verify that the point we computed is on the curve; see
            // `verify_affine_point_is_on_the_curve_scaled` for details on why. It
            // would be more secure to do the check on the affine coordinates if we
            // were going to convert to affine form (again, see
            // `verify_affine_point_is_on_the_curve_scaled` for details on why).
            // But, we're going to avoid converting to affine for performance
            // reasons, so we do the verification using the Jacobian coordinates.
            let z2 = verify_jacobian_point_is_on_the_curve(public_key_ops.common,
                                                        &product)?;

            // NSA Guide Step 7: "Compute v = xR mod n."
            // NSA Guide Step 8: "Compare v and r0. If v = r0, output VALID;
            // otherwise, output INVALID."
            //
            // Instead, we use Greg Maxwell's trick to avoid the inversion mod `q`
            // that would be necessary to compute the affine X coordinate.
            let x = public_key_ops.common.point_x(&product);
            fn sig_r_equals_x(ops: &PublicScalarOps, r: &Elem<Unencoded>,
                            x: &Elem<R>, z2: &Elem<R>) -> bool {
                let cops = ops.public_key_ops.common;
                let r_jacobian = cops.elem_product(z2, r);
                let x = cops.elem_unencoded(x);
                ops.elem_equals(&r_jacobian, &x)
            }
            let r = self.ops.scalar_as_elem(&r);
            if sig_r_equals_x(self.ops, &r, &x, &z2) {
                return Ok(());
            }
            if self.ops.elem_less_than(&r, &self.ops.q_minus_n) {
                let r_plus_n =
                    self.ops.elem_sum(&r, &public_key_ops.common.n);
                if sig_r_equals_x(self.ops, &r_plus_n, &x, &z2) {
                    return Ok(());
                }
            }
        } else {
            // GMT Guide Step B5
            // Compute  t = (r + s) mod n
            let t = scalar_sum(public_key_ops.common, &r, &s);
            if public_key_ops.common.is_zero(&t) {
                return Err(error::Unspecified);
            }

            // GMT Guide Step B6
            // Compute (x,y) = sG + tP
            let product =
                twin_mul(self.ops.private_key_ops, &s, &t, &peer_pub_key);

            // GMT Guide Step B7
            // Check (e + x) mod n == r
            let x = public_key_ops.common.point_x(&product);
            let z = public_key_ops.common.point_z(&product);
            let zz_inv = self.ops.private_key_ops.elem_inverse_squared(&z);
            let x = self.ops.public_key_ops.common.elem_product(&x, &zz_inv);

            let x = self.ops.public_key_ops.common.elem_unencoded(&x);
            let e = self.ops.scalar_as_elem(&e);
            let x_plus_e = self.ops.elem_sum(&x, &e);
            let r = self.ops.scalar_as_elem(&r);

            if self.ops.elem_equals(&x_plus_e, &r) {
                return Ok(());
            } else {
                let x_plus_e = self.ops.elem_sum(&x_plus_e, &self.ops.q_minus_n);
                if self.ops.elem_equals(&x_plus_e, &r) {
                    return Ok(());
                }
            }
        }
        Err(error::Unspecified)
    }
}

impl private::Sealed for Algorithm {}

fn split_rs_fixed<'a>(
        ops: &'static ScalarOps, input: &mut untrusted::Reader<'a>)
        -> Result<(untrusted::Input<'a>, untrusted::Input<'a>),
                  error::Unspecified> {
    let scalar_len = ops.scalar_bytes_len();
    let r = input.skip_and_get_input(scalar_len)?;
    let s = input.skip_and_get_input(scalar_len)?;
    Ok((r, s))
}

fn split_rs_asn1<'a>(
        _ops: &'static ScalarOps, input: &mut untrusted::Reader<'a>)
        -> Result<(untrusted::Input<'a>, untrusted::Input<'a>),
                  error::Unspecified> {
    der::nested(input, der::Tag::Sequence, error::Unspecified, |input| {
        let r = der::positive_integer(input)?;
        let s = der::positive_integer(input)?;
        Ok((r, s))
    })
}

fn twin_mul(ops: &PrivateKeyOps, g_scalar: &Scalar, p_scalar: &Scalar,
            p_xy: &(Elem<R>, Elem<R>)) -> Point {
    // XXX: Inefficient. TODO: implement interleaved wNAF multiplication.
    let scaled_g = ops.point_mul_base(g_scalar);
    let scaled_p = ops.point_mul(p_scalar, p_xy);
    ops.common.point_sum(&scaled_g, &scaled_p)
}


/// Verification of fixed-length (PKCS#11 style) ECDSA signatures using the
/// P-256 curve and SHA-256.
///
/// See "`ECDSA_*_FIXED` Details" in `ring::signature`'s module-level
/// documentation for more details.
pub static ECDSA_P256_SHA256_FIXED: Algorithm = Algorithm {
    ops: &p256::PUBLIC_SCALAR_OPS,
    digest_alg: &digest::SHA256,
    split_rs: split_rs_fixed,
    id: AlgorithmID::ECDSA_P256_SHA256_FIXED,
};

/// Verification of fixed-length (PKCS#11 style) ECDSA signatures using the
/// P-384 curve and SHA-384.
///
/// See "`ECDSA_*_FIXED` Details" in `ring::signature`'s module-level
/// documentation for more details.
pub static ECDSA_P384_SHA384_FIXED: Algorithm = Algorithm {
    ops: &p384::PUBLIC_SCALAR_OPS,
    digest_alg: &digest::SHA384,
    split_rs: split_rs_fixed,
    id: AlgorithmID::ECDSA_P384_SHA384_FIXED,
};

/// Verification of ASN.1 DER-encoded ECDSA signatures using the P-256 curve
/// and SHA-256.
///
/// See "`ECDSA_*_ASN1` Details" in `ring::signature`'s module-level
/// documentation for more details.
pub static ECDSA_P256_SHA256_ASN1: Algorithm = Algorithm {
    ops: &p256::PUBLIC_SCALAR_OPS,
    digest_alg: &digest::SHA256,
    split_rs: split_rs_asn1,
    id: AlgorithmID::ECDSA_P256_SHA256_ASN1,
};

/// *Not recommended*. Verification of ASN.1 DER-encoded ECDSA signatures using
/// the P-256 curve and SHA-384.
///
/// In most situations, P-256 should be used only with SHA-256 and P-384
/// should be used only with SHA-384. However, in some cases, particularly TLS
/// on the web, it is necessary to support P-256 with SHA-384 for compatibility
/// with widely-deployed implementations that do not follow these guidelines.
///
/// See "`ECDSA_*_ASN1` Details" in `ring::signature`'s module-level
/// documentation for more details.
pub static ECDSA_P256_SHA384_ASN1: Algorithm = Algorithm {
    ops: &p256::PUBLIC_SCALAR_OPS,
    digest_alg: &digest::SHA384,
    split_rs: split_rs_asn1,
    id: AlgorithmID::ECDSA_P256_SHA384_ASN1,
};

/// *Not recommended*. Verification of ASN.1 DER-encoded ECDSA signatures using
/// the P-384 curve and SHA-256.
///
/// In most situations, P-256 should be used only with SHA-256 and P-384
/// should be used only with SHA-384. However, in some cases, particularly TLS
/// on the web, it is necessary to support P-256 with SHA-384 for compatibility
/// with widely-deployed implementations that do not follow these guidelines.
///
/// See "`ECDSA_*_ASN1` Details" in `ring::signature`'s module-level
/// documentation for more details.
pub static ECDSA_P384_SHA256_ASN1: Algorithm = Algorithm {
    ops: &p384::PUBLIC_SCALAR_OPS,
    digest_alg: &digest::SHA256,
    split_rs: split_rs_asn1,
    id: AlgorithmID::ECDSA_P384_SHA256_ASN1,
};

/// Verification of ASN.1 DER-encoded ECDSA signatures using the P-384 curve
/// and SHA-384.
///
/// See "`ECDSA_*_ASN1` Details" in `ring::signature`'s module-level
/// documentation for more details.
pub static ECDSA_P384_SHA384_ASN1: Algorithm = Algorithm {
    ops: &p384::PUBLIC_SCALAR_OPS,
    digest_alg: &digest::SHA384,
    split_rs: split_rs_asn1,
    id: AlgorithmID::ECDSA_P384_SHA384_ASN1,
};

/// Verification of fixed-length (PKCS#11 style) ECDSA signatures using the
/// SM2 curve and SM3.
///
/// See "`ECDSA_*_FIXED` Details" in `ring::signature`'s module-level
/// documentation for more details.
pub static ECDSA_SM2_SM3_FIXED: Algorithm = Algorithm {
    ops: &sm2::PUBLIC_SCALAR_OPS,
    digest_alg: &digest::SM3,
    split_rs: split_rs_fixed,
    id: AlgorithmID::ECDSA_SM2_SM3_FIXED,
};

/// Verification of ASN.1 DER-encoded ECDSA signatures using the SM2 curve
/// and SM3.
///
/// See "`ECDSA_*_ASN1` Details" in `ring::signature`'s module-level
/// documentation for more details.
pub static ECDSA_SM2_SM3_ASN1: Algorithm = Algorithm {
    ops: &sm2::PUBLIC_SCALAR_OPS,
    digest_alg: &digest::SM3,
    split_rs: split_rs_asn1,
    id: AlgorithmID::ECDSA_SM2_SM3_ASN1,
};

/// Verification of fixed-length (PKCS#11 style) ECDSA signatures using the
/// SM2 curve and SHA256.
///
/// See "`ECDSA_*_FIXED` Details" in `ring::signature`'s module-level
/// documentation for more details.
pub static ECDSA_SM2_SHA256_FIXED: Algorithm = Algorithm {
    ops: &sm2::PUBLIC_SCALAR_OPS,
    digest_alg: &digest::SHA256,
    split_rs: split_rs_fixed,
    id: AlgorithmID::ECDSA_SM2_SHA256_FIXED,
};

/// Verification of ASN.1 DER-encoded ECDSA signatures using the SM2 curve
/// and SHA256.
///
/// See "`ECDSA_*_ASN1` Details" in `ring::signature`'s module-level
/// documentation for more details.
pub static ECDSA_SM2_SHA256_ASN1: Algorithm = Algorithm {
    ops: &sm2::PUBLIC_SCALAR_OPS,
    digest_alg: &digest::SHA256,
    split_rs: split_rs_asn1,
    id: AlgorithmID::ECDSA_SM2_SHA256_ASN1,
};
