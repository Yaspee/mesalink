// Copyright 2016 Brian Smith.
// Copyright 2018 Yiming Jing.
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

use core::marker::PhantomData;
use super::*;
use super::{Mont, elem_sqr_mul, elem_sqr_mul_acc};
use super::elem::{binary_op, binary_op_assign};

macro_rules! sm2_limbs {
    [$limb_7:expr, $limb_6:expr, $limb_5:expr, $limb_4:expr,
     $limb_3:expr, $limb_2:expr, $limb_1:expr, $limb_0:expr] => {
        limbs![0, 0, 0, 0,
               $limb_7, $limb_6, $limb_5, $limb_4,
               $limb_3, $limb_2, $limb_1, $limb_0]
    };
}


pub static COMMON_OPS: CommonOps = CommonOps {
    num_limbs: 256 / LIMB_BITS,

    q: Mont {
        p: sm2_limbs![0xfffffffe, 0xffffffff, 0xffffffff, 0xffffffff,
                      0xffffffff, 0x00000000, 0xffffffff, 0xffffffff],
        // 2**512 % p
        rr: sm2_limbs![0x00000004, 0x00000002, 0x00000001, 0x00000001,
                       0x00000002, 0xffffffff, 0x00000002, 0x00000003],
    },

    n: Elem {
        limbs: sm2_limbs![0xfffffffe, 0xffffffff, 0xffffffff, 0xffffffff,
                          0x7203df6b, 0x21c6052b, 0x53bbf409, 0x39d54123],
        m: PhantomData,
        encoding: PhantomData, // Unencoded
    },

    a: Elem {
        // (a * 2**256) %p
        limbs: sm2_limbs![0xfffffffb, 0xffffffff, 0xffffffff, 0xffffffff,
                          0xfffffffc, 0x00000003, 0xffffffff, 0xfffffffc],
        m: PhantomData,
        encoding: PhantomData, // R
    },
    b: Elem {
        // (b * 2**256) %p
        limbs: sm2_limbs![0x240fe188, 0xba20e2c8, 0x52798150, 0x5ea51c3c,
                          0x71cf379a, 0xe9b537ab, 0x90d23063, 0x2bc0dd42],
        m: PhantomData,
        encoding: PhantomData, // R
    },

    elem_add_impl: GFp_sm2_elem_add,
    elem_mul_mont: GFp_sm2_elem_mul_mont,
    elem_sqr_mont: GFp_sm2_elem_sqr_mont,

    point_add_jacobian_impl: GFp_sm2_point_add,
};


pub static PRIVATE_KEY_OPS: PrivateKeyOps = PrivateKeyOps {
    common: &COMMON_OPS,
    elem_inv_squared: sm2_elem_inv_squared,
    point_mul_base_impl: sm2_point_mul_base_impl,
    point_mul_impl: GFp_sm2_point_mul,
};

fn sm2_elem_inv_squared(a: &Elem<R>) -> Elem<R> {
    // Calculate a**-2 (mod q) == a**(q - 3) (mod q)
    //
    // The exponent (q - 3) is:
    //
    //    0xfffffffeffffffffffffffffffffffffffffffff00000000fffffffffffffffc

    #[inline]
    fn sqr_mul(a: &Elem<R>, squarings: usize, b: &Elem<R>) -> Elem<R> {
        elem_sqr_mul(&COMMON_OPS, a, squarings, b)
    }

    #[inline]
    fn sqr_mul_acc(a: &mut Elem<R>, squarings: usize, b: &Elem<R>) {
        elem_sqr_mul_acc(&COMMON_OPS, a, squarings, b)
    }

    let b_1 = &a;
    let b_11       = sqr_mul(b_1,          1, b_1); // 2
    let b_111      = sqr_mul(&b_11,        1, b_1); // 3
    let f_11       = sqr_mul(&b_111,       3, &b_111); // 6
    let fff        = sqr_mul(&f_11,        6, &f_11); // 12
    let fff_111    = sqr_mul(&fff,         3, &b_111); // 15
    let fffffff_11 = sqr_mul(&fff_111,    15, &fff_111); // 30
    let ffffffff   = sqr_mul(&fffffff_11,  2, &b_11); // 32
    let ffffffffffffffff = sqr_mul(&ffffffff, 32, &ffffffff); // 64

    // fffffff_111
    let mut acc = sqr_mul(&fffffff_11, 1, &b_1); // 31

    // fffffffe
    COMMON_OPS.elem_square(&mut acc);

    // fffffffeffffffffffffffff
    sqr_mul_acc(&mut acc, 64, &ffffffffffffffff);

    // fffffffeffffffffffffffffffffffffffffffff
    sqr_mul_acc(&mut acc, 64, &ffffffffffffffff);

    // fffffffeffffffffffffffffffffffffffffffff00000000ffffffff
    sqr_mul_acc(&mut acc, 64, &ffffffff);

    // fffffffeffffffffffffffffffffffffffffffff00000000fffffffffffffff_11
    sqr_mul_acc(&mut acc, 30, &fffffff_11);

    // fffffffeffffffffffffffffffffffffffffffff00000000fffffffffffffffc
    COMMON_OPS.elem_square(&mut acc);
    COMMON_OPS.elem_square(&mut acc);

    acc
}

fn sm2_point_mul_base_impl(a: &Scalar) -> Point {
    static SM2_GENERATOR: (Elem<R>, Elem<R>) = (
        // x * 2**256 %p
        Elem {
            limbs: sm2_limbs![0x91167a5e, 0xe1c13b05, 0xd6a1ed99, 0xac24c3c3,
                              0x3e7981ed, 0xdca6c050, 0x61328990, 0xf418029e],
            m: PhantomData,
            encoding: PhantomData,
        },
        // y * 2**256 %p
        Elem {
            limbs: sm2_limbs![0x63cd65d4, 0x81d735bd, 0x8d4cfb06, 0x6e2a48f8,
                              0xc1f5e578, 0x8d3295fa, 0xc1354e59, 0x3c2d0ddd],
            m: PhantomData,
            encoding: PhantomData,
        }
    );

    PRIVATE_KEY_OPS.point_mul(a, &SM2_GENERATOR)
}

pub static PUBLIC_KEY_OPS: PublicKeyOps = PublicKeyOps { common: &COMMON_OPS };

pub static SCALAR_OPS: ScalarOps = ScalarOps {
    common: &COMMON_OPS,
    scalar_inv_to_mont_impl: sm2_scalar_inv_to_mont,
    scalar_mul_mont: GFp_sm2_scalar_mul_mont,
};

pub static PUBLIC_SCALAR_OPS: PublicScalarOps = PublicScalarOps {
    scalar_ops: &SCALAR_OPS,
    public_key_ops: &PUBLIC_KEY_OPS,
    private_key_ops: &PRIVATE_KEY_OPS,

    // (p - n) %p
    q_minus_n: Elem {
        limbs: sm2_limbs![0, 0, 0, 0, 0x8dfc2093, 0xde39fad5, 0xac440bf6,
                           0xc62abedc],
        m: PhantomData,
        encoding: PhantomData, // Unencoded
    },
};

pub static PRIVATE_SCALAR_OPS: PrivateScalarOps = PrivateScalarOps {
    scalar_ops: &SCALAR_OPS,

    oneRR_mod_n: Scalar {
        limbs: N_RR_LIMBS,
        m: PhantomData,
        encoding: PhantomData, // R
    },
};

fn sm2_scalar_inv_to_mont(a: &Scalar<Unencoded>) -> Scalar<R> {
    // Calculate the modular inverse of scalar |a| using Fermat's Little
    // Theorem:
    //
    //    a**-1 (mod n) == a**(n - 2) (mod n)
    //
    // The exponent (n - 2) is:
    //
    //    0xfffffffeffffffffffffffffffffffff7203df6b21c6052b53bbf40939d54121

    fn mul(a: &Scalar<R>, b: &Scalar<R>) -> Scalar<R> {
        binary_op(GFp_sm2_scalar_mul_mont, a, b)
    }

    fn sqr(a: &Scalar<R>) -> Scalar<R> {
        binary_op(GFp_sm2_scalar_mul_mont, a, a)
    }

    fn sqr_mut(a: &mut Scalar<R>) {
        unary_op_from_binary_op_assign(GFp_sm2_scalar_mul_mont, a);
    }

    // Returns (`a` squared `squarings` times) * `b`.
    fn sqr_mul(a: &Scalar<R>, squarings: usize, b: &Scalar<R>) -> Scalar<R> {
        debug_assert!(squarings >= 1);
        let mut tmp = sqr(a);
        for _ in 1..squarings {
            sqr_mut(&mut tmp);
        }
        mul(&tmp, b)
    }

    // Sets `acc` = (`acc` squared `squarings` times) * `b`.
    fn sqr_mul_acc(acc: &mut Scalar<R>, squarings: usize, b: &Scalar<R>) {
        debug_assert!(squarings >= 1);
        for _ in 0..squarings {
            sqr_mut(acc);
        }
        binary_op_assign(GFp_sm2_scalar_mul_mont, acc, b)
    }

    fn to_mont(a: &Scalar<Unencoded>) -> Scalar<R> {
        static N_RR: Scalar<Unencoded> = Scalar {
            limbs: N_RR_LIMBS,
            m: PhantomData,
            encoding: PhantomData
        };
        binary_op(GFp_sm2_scalar_mul_mont, a, &N_RR)
    }

    // Indexes into `d`.
    const B_1: usize = 0;
    const B_10: usize = 1;
    const B_11: usize = 2;
    const B_101: usize = 3;
    const B_111: usize = 4;
    const B_1111: usize = 5;
    const B_10101: usize = 6;
    const B_101111: usize = 7;
    const DIGIT_COUNT: usize = 8;

    let mut d = [Scalar::zero(); DIGIT_COUNT];

    d[B_1] = to_mont(a);
    d[B_10] = sqr(&d[B_1]);
    d[B_11] = mul(&d[B_10], &d[B_1]);
    d[B_101] = mul(&d[B_10], &d[B_11]);
    d[B_111] = mul(&d[B_101], &d[B_10]);
    let b_1010 = sqr(&d[B_101]);
    d[B_1111] = mul(&b_1010, &d[B_101]);
    d[B_10101] = sqr_mul(&b_1010, 0 + 1, &d[B_1]);
    let b_101010 = sqr(&d[B_10101]);
    d[B_101111] = mul(&b_101010, &d[B_101]);

    let f_11       = sqr_mul(&d[B_111],       3, &d[B_111]); // 6
    let fff        = sqr_mul(&f_11,           6, &f_11); // 12
    let fff_111    = sqr_mul(&fff,            3, &d[B_111]); // 15
    let fffffff_11 = sqr_mul(&fff_111,       15, &fff_111); // 30
    let fffffff_111= sqr_mul(&fffffff_11,     1, &d[B_1]); // 31
    let ffffffff   = sqr_mul(&fffffff_11,     2, &d[B_11]); // 32
    let ffffffffffffffff = sqr_mul(&ffffffff, 0 + 32, &ffffffff); // 64

    // fffffffe
    let mut acc = sqr(&fffffff_111);
    // fffffffeffffffff
    sqr_mul_acc(&mut acc, 0 + 32, &ffffffff);
    // fffffffeffffffffffffffffffffffff
    sqr_mul_acc(&mut acc, 0 + 64, &ffffffffffffffff);

    // The rest of the exponent, in binary, is:
    //
    // 0111001000000011110111110110101100100001110001100000010100101011
    // 0101001110111011111101000000100100111001110101010100000100100001

    static REMAINING_WINDOWS: [(u8, u8); 27] = [
        (1 + 3, B_111 as u8),
        (2 + 1, B_1 as u8),
        (7 + 4, B_1111 as u8),
        (1 + 4, B_1111 as u8),
        (0 + 3, B_101 as u8),
        (0 + 3, B_101 as u8),
        (1 + 2, B_11 as u8),
        (2 + 1, B_1 as u8),
        (4 + 3, B_111 as u8),
        (3 + 2, B_11 as u8),
        (6 + 3, B_101 as u8),
        (2 + 5, B_10101 as u8),
        (0 + 5, B_10101 as u8),
        (2 + 3, B_111 as u8),
        (1 + 3, B_111 as u8),
        (1 + 4, B_1111 as u8),
        (0 + 2, B_11 as u8),
        (1 + 1, B_1 as u8),
        (6 + 2, B_10 as u8),
        (1 + 2, B_10 as u8),
        (1 + 3, B_111 as u8),
        (2 + 3, B_111 as u8),
        (1 + 5, B_10101 as u8),
        (1 + 1, B_1 as u8),
        (5 + 2, B_10 as u8),
        (1 + 2, B_10 as u8),
        (3 + 1, B_1 as u8),
    ];

    for &(squarings, digit) in &REMAINING_WINDOWS {
        sqr_mul_acc(&mut acc, squarings as usize, &d[digit as usize]);
    }

    acc
}

unsafe extern fn GFp_sm2_elem_sqr_mont(
        r: *mut Limb/*[COMMON_OPS.num_limbs]*/,
        a: *const Limb/*[COMMON_OPS.num_limbs]*/) {
    // XXX: Inefficient. TODO: Make a dedicated squaring routine.
    GFp_sm2_elem_mul_mont(r, a, a);
}

const N_RR_LIMBS: [Limb; MAX_LIMBS] =
    // 2**512 % n
    sm2_limbs![0x1eb5e412, 0xa22b3d3b, 0x620fc84c, 0x3affe0d4,
               0x3464504a, 0xde6fa2fa, 0x901192af, 0x7c114f20];

extern {
    fn GFp_sm2_elem_add(r: *mut Limb/*[COMMON_OPS.num_limbs]*/,
                         a: *const Limb/*[COMMON_OPS.num_limbs]*/,
                         b: *const Limb/*[COMMON_OPS.num_limbs]*/);
    fn GFp_sm2_elem_mul_mont(r: *mut Limb/*[COMMON_OPS.num_limbs]*/,
                              a: *const Limb/*[COMMON_OPS.num_limbs]*/,
                              b: *const Limb/*[COMMON_OPS.num_limbs]*/);

    fn GFp_sm2_point_add(r: *mut Limb/*[3][COMMON_OPS.num_limbs]*/,
                              a: *const Limb/*[3][COMMON_OPS.num_limbs]*/,
                              b: *const Limb/*[3][COMMON_OPS.num_limbs]*/);
    fn GFp_sm2_point_mul(r: *mut Limb/*[3][COMMON_OPS.num_limbs]*/,
                              p_scalar: *const Limb/*[COMMON_OPS.num_limbs]*/,
                              p_x: *const Limb/*[COMMON_OPS.num_limbs]*/,
                              p_y: *const Limb/*[COMMON_OPS.num_limbs]*/);

    fn GFp_sm2_scalar_mul_mont(r: *mut Limb/*[COMMON_OPS.num_limbs]*/,
                                a: *const Limb/*[COMMON_OPS.num_limbs]*/,
                                b: *const Limb/*[COMMON_OPS.num_limbs]*/);
}
