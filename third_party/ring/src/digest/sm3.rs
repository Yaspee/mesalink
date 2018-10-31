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

use core;
use core::num::Wrapping;
use {c, polyfill};

pub type State = [u64; super::MAX_CHAINING_LEN / 8];

pub const BLOCK_LEN: usize = 512 / 8;
pub const CHAINING_LEN: usize = 256 / 8;
const CHAINING_WORDS: usize = CHAINING_LEN / 4;

type W32 = Wrapping<u32>;

macro_rules! lrot {
    ($num: expr, $bits: expr) => {
        polyfill::wrapping_rotate_left_u32($num, $bits)
    };
}

#[inline]
fn ff0(x: W32, y: W32, z: W32) -> W32 {
    x ^ y ^ z
}

#[inline]
fn ff1(x: W32, y: W32, z: W32) -> W32 {
    (x & y) | (x & z) | (y & z)
}

#[inline]
fn gg0(x: W32, y: W32, z: W32) -> W32 {
    x ^ y ^ z
}

#[inline]
fn gg1(x: W32, y: W32, z: W32) -> W32 {
    (x & y) | ((!x) & z)
}

#[inline]
fn p0(x: W32) -> W32 {
    x ^ lrot!(x, 9) ^ lrot!(x, 17)
}

#[inline]
fn p1(x: W32) -> W32 {
    x ^ lrot!(x, 15) ^ lrot!(x, 23)
}

pub unsafe extern fn block_data_order(
    state: &mut State,
    data: *const u8,
    num: c::size_t,
) {
    let data = data as *const [u8; BLOCK_LEN];
    let blocks = core::slice::from_raw_parts(data, num);
    block_data_order_safe(state, blocks)
}

fn block_data_order_safe(state: &mut State, blocks: &[[u8; BLOCK_LEN]]) {
    let state = polyfill::slice::u64_as_u32_mut(state);
    let state = polyfill::slice::as_wrapping_mut(state);
    let state = &mut state[..CHAINING_WORDS];
    let state = slice_as_array_ref_mut!(state, CHAINING_WORDS).unwrap();

    let mut w: [W32; 68] = [Wrapping(0); 68];
    let mut w1: [W32; 64] = [Wrapping(0); 64];
    for block in blocks {
        for j in 0..16 {
            let word = slice_as_array_ref!(&block[j * 4..][..4], 4).unwrap();
            w[j] = Wrapping(polyfill::slice::u32_from_be_u8(word))
        }
        for j in 16..68 {
            w[j] = p1(w[j - 16] ^ w[j - 9] ^ lrot!(w[j - 3], 15))
                ^ lrot!(w[j - 13], 7)
                ^ w[j - 6];
        }
        for j in 0..64 {
            w1[j] = w[j] ^ w[j + 4];
        }

        let mut a = state[0];
        let mut b = state[1];
        let mut c = state[2];
        let mut d = state[3];
        let mut e = state[4];
        let mut f = state[5];
        let mut g = state[6];
        let mut h = state[7];

        for j in 0..64 {
            let (t, mut tt1, mut tt2) = match j {
                0...15 => {
                    (Wrapping(0x79cc_4519u32), ff0(a, b, c), gg0(e, f, g))
                }
                16...63 => {
                    (Wrapping(0x7a87_9d8au32), ff1(a, b, c), gg1(e, f, g))
                }
                _ => unreachable!(),
            };
            let ss1 = lrot!(lrot!(a, 12) + e + lrot!(t, j as u32), 7);
            let ss2 = ss1 ^ lrot!(a, 12);
            tt1 = tt1 + d + ss2 + w1[j];
            tt2 = tt2 + h + ss1 + w[j];
            d = c;
            c = lrot!(b, 9);
            b = a;
            a = tt1;
            h = g;
            g = lrot!(f, 19);
            f = e;
            e = p0(tt2);
        }

        state[0] = a ^ state[0];
        state[1] = b ^ state[1];
        state[2] = c ^ state[2];
        state[3] = d ^ state[3];
        state[4] = e ^ state[4];
        state[5] = f ^ state[5];
        state[6] = g ^ state[6];
        state[7] = h ^ state[7];
    }
}
