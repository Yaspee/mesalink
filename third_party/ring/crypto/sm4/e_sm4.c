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

#include <string.h>
#include <GFp/sm4.h>

#include "../fipsmodule/modes/internal.h"
#include "internal.h"

#define EVP_AEAD_SM4_GCM_NONCE_LEN 12
#define EVP_AEAD_SM4_GCM_TAG_LEN 16

// Declarations for extern functions only called by Rust code, to avoid
// -Wmissing-prototypes warnings.
int GFp_sm4_gcm_init(uint8_t *ctx_buf, size_t ctx_buf_len, const uint8_t *key,
                     size_t key_len);
int GFp_sm4_gcm_open(const uint8_t *ctx_buf, uint8_t *out, size_t in_out_len,
                     uint8_t tag_out[EVP_AEAD_SM4_GCM_TAG_LEN],
                     const uint8_t nonce[EVP_AEAD_SM4_GCM_NONCE_LEN],
                     const uint8_t *in, const uint8_t *ad, size_t ad_len);
int GFp_sm4_gcm_seal(const uint8_t *ctx_buf, uint8_t *in_out, size_t in_out_len,
                     uint8_t tag_out[EVP_AEAD_SM4_GCM_TAG_LEN],
                     const uint8_t nonce[EVP_AEAD_SM4_GCM_NONCE_LEN],
                     const uint8_t *ad, size_t ad_len);
int GFp_SM4_set_encrypt_key(const uint8_t *user_key, SM4_KEY *key);
void GFp_SM4_encrypt(const uint8_t *in, uint8_t *out, const SM4_KEY *key);

#if !defined(GFp_C_SM4)
int GFp_asm_SM4_set_encrypt_key(const uint8_t *key, unsigned bits,
                                SM4_KEY *sm4_key);
void GFp_asm_SM4_encrypt(const uint8_t *in, uint8_t *out, const SM4_KEY *key);
#endif

static void sm4_ctr32_encrypt_blocks(const uint8_t *in, uint8_t *out,
                                     size_t len, const SM4_KEY *key,
                                     const uint8_t ivec[16]);

int GFp_SM4_set_encrypt_key(const uint8_t *user_key, SM4_KEY *key) {
  // Keep this in sync with |gcm128_init_gmult_ghash| and |sms4_ctr|.

#if defined(GFp_C_SM4)
  return GFp_sm4_c_set_encrypt_key(user_key, key);
#else
  return GFp_sm4_asm_set_encrypt_key(user_key, key);
#endif
}

static sm4_block_f sm4_block(void) {
  // Keep this in sync with |GFp_SM4_set_encrypt_key| and |sm4_ctr|.

#if defined(GFp_C_SM4)
  return GFp_sm4_c_encrypt;
#else
  return GFp_SM4_asm_encrypt;
#endif
}

void GFp_SM4_encrypt(const uint8_t *in, uint8_t *out, const SM4_KEY *key) {
  (sm4_block())(in, out, key);
}

static sm4_ctr_f sm4_ctr(void) {
  // Keep this in sync with |set_set_key| and |sm4_block|.
  return sm4_ctr32_encrypt_blocks;
}

static void sm4_ctr32_encrypt_blocks(const uint8_t *in, uint8_t *out,
                                     size_t blocks, const SM4_KEY *key,
                                     const uint8_t ivec[16]) {
  alignas(16) uint8_t counter_plaintext[16];
  memcpy(counter_plaintext, ivec, 16);
  uint32_t counter = from_be_u32_ptr(&counter_plaintext[12]);

  sm4_block_f block = sm4_block();

  for (size_t current_block = 0; current_block < blocks; ++current_block) {
    alignas(16) uint8_t counter_ciphertext[16];
    block(counter_plaintext, counter_ciphertext, key);
    for (size_t i = 0; i < 16; ++i) {
      out[i] = in[i] ^ counter_ciphertext[i];
    }
    // The caller must ensure the counter won't wrap around.
    ++counter;
    assert(counter != 0);
    to_be_u32_ptr(&counter_plaintext[12], counter);
    out += 16;
    in += 16;
  }
}

int GFp_sm4_gcm_init(uint8_t *ctx_buf, size_t ctx_buf_len, const uint8_t *key,
                     size_t key_len) {
  alignas(16) SM4_KEY ks;
  if (key_len != 16) {
    return 0;
  }
  assert(ctx_buf_len >= sizeof(ks) + GCM128_SERIALIZED_LEN);
  if (ctx_buf_len < sizeof(ks) + GCM128_SERIALIZED_LEN) {
    return 0;
  }

  // XXX: Ignores return value. TODO: These functions should return |void|
  // anyway.
  GFp_SM4_set_encrypt_key(key, &ks);

  GFp_gcm128_init_serialized(ctx_buf + sizeof(ks), &ks, sm4_block());
  memcpy(ctx_buf, &ks, sizeof(ks));
  return 1;
}

static int gfp_sm4_gcm_init_and_aad(GCM128_CONTEXT *gcm, SM4_KEY *ks,
                                    const uint8_t *ctx_buf,
                                    const uint8_t nonce[], const uint8_t ad[],
                                    size_t ad_len) {
  assert(ad != NULL || ad_len == 0);
  memcpy(ks, ctx_buf, sizeof(*ks));

  GFp_gcm128_init(gcm, ks, sm4_block(), ctx_buf + sizeof(*ks), nonce);
  return GFp_gcm128_aad(gcm, ad, ad_len);
}

int GFp_sm4_gcm_seal(const uint8_t *ctx_buf, uint8_t *in_out, size_t in_out_len,
                     uint8_t tag_out[EVP_AEAD_SM4_GCM_TAG_LEN],
                     const uint8_t nonce[EVP_AEAD_SM4_GCM_NONCE_LEN],
                     const uint8_t *ad, size_t ad_len) {
  assert(in_out != NULL || in_out_len == 0);
  assert(ad != NULL || ad_len == 0);

  GCM128_CONTEXT gcm;
  alignas(16) SM4_KEY ks;
  if (!gfp_sm4_gcm_init_and_aad(&gcm, &ks, ctx_buf, nonce, ad, ad_len)) {
    return 0;
  }
  if (in_out_len > 0) {
    sm4_ctr_f ctr = sm4_ctr();
    if (!GFp_gcm128_encrypt_ctr32(&gcm, &ks, in_out, in_out, in_out_len, ctr)) {
      return 0;
    }
  }
  GFp_gcm128_tag(&gcm, tag_out);
  return 1;
}

int GFp_sm4_gcm_open(const uint8_t *ctx_buf, uint8_t *out, size_t in_out_len,
                     uint8_t tag_out[EVP_AEAD_SM4_GCM_TAG_LEN],
                     const uint8_t nonce[EVP_AEAD_SM4_GCM_NONCE_LEN],
                     const uint8_t *in, const uint8_t *ad, size_t ad_len) {
  assert(out != NULL || in_out_len == 0);
  assert(in != NULL || in_out_len == 0);
  assert(ad != NULL || ad_len == 0);

  GCM128_CONTEXT gcm;
  alignas(16) SM4_KEY ks;
  if (!gfp_sm4_gcm_init_and_aad(&gcm, &ks, ctx_buf, nonce, ad, ad_len)) {
    return 0;
  }
  if (in_out_len > 0) {
    sm4_ctr_f ctr = sm4_ctr();
    if (!GFp_gcm128_decrypt_ctr32(&gcm, &ks, in, out, in_out_len, ctr)) {
      return 0;
    }
  }
  GFp_gcm128_tag(&gcm, tag_out);
  return 1;
}
