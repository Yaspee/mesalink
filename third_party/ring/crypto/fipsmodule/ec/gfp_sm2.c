/* Copyright 2016 Brian Smith.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHORS DISCLAIM ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
 * OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE. */

#include "ecp_sm2.h"
#include "../../limbs/limbs.h"

#include "../../internal.h"
#include "../bn/internal.h"
#include "../../limbs/limbs.inl"

typedef Limb Elem[SM2_LIMBS];
typedef Limb ScalarMont[SM2_LIMBS];
typedef Limb Scalar[SM2_LIMBS];

/* Prototypes to avoid -Wmissing-prototypes warnings. */
void GFp_sm2_elem_add(Elem r, const Elem a, const Elem b);
void GFp_sm2_elem_sub(Elem r, const Elem a, const Elem b);
void GFp_sm2_elem_div_by_2(Elem r, const Elem a);
void GFp_sm2_elem_mul_mont(Elem r, const Elem a, const Elem b);
void GFp_sm2_elem_neg(Elem r, const Elem a);
void GFp_sm2_scalar_inv_to_mont(ScalarMont r, const Scalar a);
void GFp_sm2_scalar_mul_mont(ScalarMont r, const ScalarMont a,
                              const ScalarMont b);
void GFp_sm2_scalar_sqr_mont(ScalarMont r, const ScalarMont a);
void GFp_sm2_scalar_sqr_rep_mont(ScalarMont r, const ScalarMont a, int rep);

void GFp_sm2_select_w5(SM2_POINT *out, const SM2_POINT table[16],
                            int index);
void GFp_sm2_select_w7(SM2_POINT_AFFINE *out,
                            const SM2_POINT_AFFINE table[64], int index);

static const BN_ULONG Q[SM2_LIMBS] = {
  TOBN(0xffffffff, 0xffffffff),
  TOBN(0xffffffff, 0x00000000),
  TOBN(0xffffffff, 0xffffffff),
  TOBN(0xfffffffe, 0xffffffff),
};

static const BN_ULONG N[SM2_LIMBS] = {
    TOBN(0x53bbf409, 0x39d54123),
    TOBN(0x7203df6b, 0x21c6052b),
    TOBN(0xffffffff, 0xffffffff),
    TOBN(0xfffffffe, 0xffffffff),
};

/* One converted into the Montgomery domain */
// 2**256 % p
static const Limb ONE[SM2_LIMBS] = {
    TOBN(0x00000000, 0x00000001), TOBN(0x00000000, 0xffffffff),
    TOBN(0x00000000, 0x00000000), TOBN(0x00000001, 0x00000000),
};

/* XXX: MSVC for x86 warns when it fails to inline these functions it should
 * probably inline. */
#if defined(_MSC_VER)  && defined(OPENSSL_X86)
#define INLINE_IF_POSSIBLE __forceinline
#else
#define INLINE_IF_POSSIBLE inline
#endif


static INLINE_IF_POSSIBLE Limb is_equal(const Elem a, const Elem b) {
  return LIMBS_equal(a, b, SM2_LIMBS);
}

static INLINE_IF_POSSIBLE void copy_conditional(Elem r, const Elem a,
                                                const Limb condition) {
  for (size_t i = 0; i < SM2_LIMBS; ++i) {
    r[i] = constant_time_select_w(condition, a[i], r[i]);
  }
}

static void elem_add(Elem r, const Elem a, const Elem b) {
  LIMBS_add_mod(r, a, b, Q, SM2_LIMBS);
}

static void elem_sub(Elem r, const Elem a, const Elem b) {
  LIMBS_sub_mod(r, a, b, Q, SM2_LIMBS);
}

static void elem_div_by_2(Elem r, const Elem a) {
  /* Consider the case where `a` is even. Then we can shift `a` right one bit
   * and the result will still be valid because we didn't lose any bits and so
   * `(a >> 1) * 2 == a (mod q)`, which is the invariant we must satisfy.
   *
   * The remainder of this comment is considering the case where `a` is odd.
   *
   * Since `a` is odd, it isn't the case that `(a >> 1) * 2 == a (mod q)`
   * because the lowest bit is lost during the shift. For example, consider:
   *
   * ```python
   * q = 2**384 - 2**128 - 2**96 + 2**32 - 1
   * a = 2**383
   * two_a = a * 2 % q
   * assert two_a == 0x100000000ffffffffffffffff00000001
   * ```
   *
   * Notice there how `(2 * a) % q` wrapped around to a smaller odd value. When
   * we divide `two_a` by two (mod q), we need to get the value `2**383`, which
   * we obviously can't get with just a right shift.
   *
   * `q` is odd, and `a` is odd, so `a + q` is even. We could calculate
   * `(a + q) >> 1` and then reduce it mod `q`. However, then we would have to
   * keep track of an extra most significant bit. We can avoid that by instead
   * calculating `(a >> 1) + ((q + 1) >> 1)`. The `1` in `q + 1` is the least
   * significant bit of `a`. `q + 1` is even, which means it can be shifted
   * without losing any bits. Since `q` is odd, `q - 1` is even, so the largest
   * odd field element is `q - 2`. Thus we know that `a <= q - 2`. We know
   * `(q + 1) >> 1` is `(q + 1) / 2` since (`q + 1`) is even. The value of
   * `a >> 1` is `(a - 1)/2` since the shift will drop the least significant
   * bit of `a`, which is 1. Thus:
   *
   * sum  =  ((q + 1) >> 1) + (a >> 1)
   * sum  =  (q + 1)/2 + (a >> 1)       (substituting (q + 1)/2)
   *     <=  (q + 1)/2 + (q - 2 - 1)/2  (substituting a <= q - 2)
   *     <=  (q + 1)/2 + (q - 3)/2      (simplifying)
   *     <=  (q + 1 + q - 3)/2          (factoring out the common divisor)
   *     <=  (2q - 2)/2                 (simplifying)
   *     <=  q - 1                      (simplifying)
   *
   * Thus, no reduction of the sum mod `q` is necessary. */

  Limb is_odd = constant_time_is_nonzero_w(a[0] & 1);

  /* r = a >> 1. */
  Limb carry = a[SM2_LIMBS - 1] & 1;
  r[SM2_LIMBS - 1] = a[SM2_LIMBS - 1] >> 1;
  for (size_t i = 1; i < SM2_LIMBS; ++i) {
    Limb new_carry = a[SM2_LIMBS - i - 1];
    r[SM2_LIMBS - i - 1] =
        (a[SM2_LIMBS - i - 1] >> 1) | (carry << (LIMB_BITS - 1));
    carry = new_carry;
  }

  // ((p+1)>>1) % p
  static const Elem Q_PLUS_1_SHR_1 = {
    TOBN(0x80000000, 0x00000000), TOBN(0xffffffff, 0x80000000),
    TOBN(0xffffffff, 0xffffffff), TOBN(0x7fffffff, 0x7fffffff),
  };

  Elem adjusted;
  BN_ULONG carry2 = limbs_add(adjusted, r, Q_PLUS_1_SHR_1, SM2_LIMBS);
#if defined(NDEBUG)
  (void)carry2;
#endif
  assert(carry2 == 0);

  copy_conditional(r, adjusted, is_odd);
}

static inline void elem_mul_mont(Elem r, const Elem a, const Elem b) {
  static const BN_ULONG Q_N0[] = {
    // (-1 % 2**256)*modinv(p, 2**256) % 2**256, the last 64 bits
    BN_MONT_CTX_N0(0x0, 0x1)
  };
  /* XXX: Not (clearly) constant-time; inefficient.*/
  GFp_bn_mul_mont(r, a, b, Q, Q_N0, SM2_LIMBS);
}

static inline void elem_mul_by_2(Elem r, const Elem a) {
  LIMBS_shl_mod(r, a, Q, SM2_LIMBS);
}

static INLINE_IF_POSSIBLE void elem_mul_by_3(Elem r, const Elem a) {
  /* XXX: inefficient. TODO: Replace with an integrated shift + add. */
  Elem doubled;
  elem_add(doubled, a, a);
  elem_add(r, doubled, a);
}

static inline void elem_sqr_mont(Elem r, const Elem a) {
  /* XXX: Inefficient. TODO: Add a dedicated squaring routine. */
  elem_mul_mont(r, a, a);
}

void GFp_sm2_elem_add(Elem r, const Elem a, const Elem b) {
  elem_add(r, a, b);
}

void GFp_sm2_elem_sub(Elem r, const Elem a, const Elem b) {
  elem_sub(r, a, b);
}

void GFp_sm2_elem_div_by_2(Elem r, const Elem a) {
  elem_div_by_2(r, a);
}

void GFp_sm2_elem_mul_mont(Elem r, const Elem a, const Elem b) {
  elem_mul_mont(r, a, b);
}

void GFp_sm2_elem_neg(Elem r, const Elem a) {
  Limb is_zero = LIMBS_are_zero(a, SM2_LIMBS);
  Carry borrow = limbs_sub(r, Q, a, SM2_LIMBS);
#if defined(NDEBUG)
  (void)borrow;
#endif
  assert(borrow == 0);
  for (size_t i = 0; i < SM2_LIMBS; ++i) {
    r[i] = constant_time_select_w(is_zero, 0, r[i]);
  }
}

void GFp_sm2_scalar_mul_mont(ScalarMont r, const ScalarMont a,
                              const ScalarMont b) {
  static const BN_ULONG N_N0[] = {
    // (-1 % 2**256)*modinv(n, 2**256) % 2**256, the last 64 bits
    BN_MONT_CTX_N0(0x327f9e88, 0x72350975)
  };
  /* XXX: Inefficient. TODO: Add dedicated multiplication routine. */
  GFp_bn_mul_mont(r, a, b, N, N_N0, SM2_LIMBS);
}

void GFp_sm2_scalar_sqr_mont(ScalarMont r, const ScalarMont a) {
  GFp_sm2_scalar_mul_mont(r, a, a);
}

void GFp_sm2_scalar_sqr_rep_mont(ScalarMont r, const ScalarMont a, int rep) {
  assert(rep >= 1);
  GFp_sm2_scalar_sqr_mont(r, a);
  for (int i = 1; i < rep; ++i) {
    GFp_sm2_scalar_sqr_mont(r, r);
  }
}

/* TODO(perf): Optimize this. */

static void GFp_sm2_point_select_w5(SM2_POINT *out,
                                     const SM2_POINT table[16], size_t index) {
  Elem x; memset(x, 0, sizeof(x));
  Elem y; memset(y, 0, sizeof(y));
  Elem z; memset(z, 0, sizeof(z));

  for (size_t i = 0; i < 16; ++i) {
    Limb mask = constant_time_eq_w(index, i + 1);
    for (size_t j = 0; j < SM2_LIMBS; ++j) {
      x[j] |= table[i].X[j] & mask;
      y[j] |= table[i].Y[j] & mask;
      z[j] |= table[i].Z[j] & mask;
    }
  }

  limbs_copy(out->X, x, SM2_LIMBS);
  limbs_copy(out->Y, y, SM2_LIMBS);
  limbs_copy(out->Z, z, SM2_LIMBS);
}


#include "ecp_sm2.inl"
