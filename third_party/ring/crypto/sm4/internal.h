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

#ifndef HEADER_SM4_INTERNAL_H
#define HEADER_SM4_INTERNAL_H

#include <GFp/cpu.h>
#include <GFp/sm4.h>
#include "../fipsmodule/modes/internal.h"
#include <stdlib.h>

#if defined(__cplusplus)
extern "C" {
#endif

typedef aes_block_f sm4_block_f;
typedef aes_ctr_f sm4_ctr_f;

#define GFp_C_SM4
int GFp_sm4_c_set_encrypt_key(const uint8_t *key, SM4_KEY *sm4_key);
void GFp_sm4_c_encrypt(const uint8_t *in, uint8_t *out, const SM4_KEY *key);

#if defined(__cplusplus)
}  // extern C
#endif

#endif  // HEADER_SM4_INTERNAL_H
