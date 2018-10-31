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

use {aead, bssl, c, error, polyfill};

/// SM4 in GCM mode with 128-bit tags and 96 bit nonces.
///
/// C analog: `EVP_aead_sms4_gcm` in gmSSL
///
pub static SM4_GCM: aead::Algorithm = aead::Algorithm {
    key_len: SM4_KEY_LEN,
    init: sm4_gcm_init,
    seal: sm4_gcm_seal,
    open: sm4_gcm_open,
    id: aead::AlgorithmID::SM4_GCM,
    max_input_len: SM4_GCM_MAX_INPUT_LEN,
};

const SM4_KEY_LEN: usize = 128 / 8;
const SM4_BLOCK_LEN: u64 = 16;
const SM4_GCM_OVERHEAD_BLOCKS_PER_NONCE: u64 = 2;
const SM4_GCM_MAX_INPUT_LEN: u64 =
    max_input_len!(SM4_BLOCK_LEN, SM4_GCM_OVERHEAD_BLOCKS_PER_NONCE);

// const SM4_MAX_ROUNDS: usize = 32;
// const SM4_KEY_BUF_LEN: usize = (4 * 4 * (SM4_MAX_ROUNDS + 1)) + 8;
// const SM4_SERIALIZED_LEN: usize = 16 * 16;
// pub const SM4_KEY_CTX_BUF_LEN: usize = SM4_KEY_BUF_LEN + SM4_SERIALIZED_LEN;

fn sm4_gcm_init(
    ctx_buf: &mut [u8],
    key: &[u8],
) -> Result<(), error::Unspecified> {
    bssl::map_result(unsafe {
        GFp_sm4_gcm_init(
            ctx_buf.as_mut_ptr(),
            ctx_buf.len(),
            key.as_ptr(),
            key.len(),
        )
    })
}

fn sm4_gcm_seal(
    ctx: &[u64; aead::KEY_CTX_BUF_ELEMS],
    nonce: &[u8; aead::NONCE_LEN],
    ad: &[u8],
    in_out: &mut [u8],
    tag: &mut [u8; aead::TAG_LEN],
) -> Result<(), error::Unspecified> {
    let ctx = polyfill::slice::u64_as_u8(ctx);
    bssl::map_result(unsafe {
        GFp_sm4_gcm_seal(
            ctx.as_ptr(),
            in_out.as_mut_ptr(),
            in_out.len(),
            tag,
            nonce,
            ad.as_ptr(),
            ad.len(),
        )
    })
}

fn sm4_gcm_open(
    ctx: &[u64; aead::KEY_CTX_BUF_ELEMS],
    nonce: &[u8; aead::NONCE_LEN],
    ad: &[u8],
    in_prefix_len: usize,
    in_out: &mut [u8],
    tag_out: &mut [u8; aead::TAG_LEN],
) -> Result<(), error::Unspecified> {
    let ctx = polyfill::slice::u64_as_u8(ctx);
    bssl::map_result(unsafe {
        GFp_sm4_gcm_open(
            ctx.as_ptr(),
            in_out.as_mut_ptr(),
            in_out.len() - in_prefix_len,
            tag_out,
            nonce,
            in_out[in_prefix_len..].as_ptr(),
            ad.as_ptr(),
            ad.len(),
        )
    })
}

extern {
    fn GFp_sm4_gcm_init(
        ctx_buf: *mut u8,
        ctx_buf_len: c::size_t,
        key: *const u8,
        key_len: c::size_t,
    ) -> c::int;

    fn GFp_sm4_gcm_seal(
        ctx_buf: *const u8,
        in_out: *mut u8,
        in_out_len: c::size_t,
        tag_out: &mut [u8; aead::TAG_LEN],
        nonce: &[u8; aead::NONCE_LEN],
        ad: *const u8,
        ad_len: c::size_t,
    ) -> c::int;

    fn GFp_sm4_gcm_open(
        ctx_buf: *const u8,
        out: *mut u8,
        in_out_len: c::size_t,
        tag_out: &mut [u8; aead::TAG_LEN],
        nonce: &[u8; aead::NONCE_LEN],
        in_: *const u8,
        ad: *const u8,
        ad_len: c::size_t,
    ) -> c::int;
}
