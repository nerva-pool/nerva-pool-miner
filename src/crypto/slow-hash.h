// Copyright (c) 2018, The NERVA Project
// Copyright (c) 2018, The Masari Project
// Copyright (c) 2014-2018, The Monero Project
//
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without modification, are
// permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this list of
//    conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice, this list
//    of conditions and the following disclaimer in the documentation and/or other
//    materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its contributors may be
//    used to endorse or promote products derived from this software without specific
//    prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//
// Parts of this file are originally copyright (c) 2012-2013 The Cryptonote developers

#ifndef SLOW_HASH_H
#define SLOW_HASH_H

#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <math.h>

#include "int-util.h"
#include "oaes_lib.h"

#define MEMORY 1048576
#define SALT_MEMORY 262144
#define AES_BLOCK_SIZE 16
#define AES_KEY_SIZE 32
#define INIT_SIZE_BLK 8
extern void aesb_single_round(const uint8_t *in, uint8_t *out, const uint8_t *expandedKey);
extern void aesb_pseudo_round(const uint8_t *in, uint8_t *out, const uint8_t *expandedKey);

#define NONCE_POINTER (((const uint8_t *)data) + 35)

#if defined(_MSC_VER)
#define THREADV __declspec(thread)
#else
#define THREADV __thread
#endif

#if !defined NO_AES && (defined(__x86_64__) || (defined(_MSC_VER) && defined(_WIN64)))

#define VARIANT1_1(p)                                          \
    const uint8_t tmp = ((const uint8_t *)(p))[11];            \
    static const uint32_t table = 0x75310;                     \
    const uint8_t index = (((tmp >> 3) & 6) | (tmp & 1)) << 1; \
    ((uint8_t *)(p))[11] = tmp ^ ((table >> index) & 0x30);

#define VARIANT1_2(p) \
    xor64(p, tweak1_2);

#include <emmintrin.h>

#if defined(_MSC_VER)
#include <intrin.h>
#include <windows.h>
#define STATIC
#define INLINE __inline
#if !defined(RDATA_ALIGN16)
#define RDATA_ALIGN16 __declspec(align(16))
#endif
#elif defined(__MINGW32__)
#include <intrin.h>
#include <windows.h>
#define STATIC static
#define INLINE inline
#if !defined(RDATA_ALIGN16)
#define RDATA_ALIGN16 __attribute__((aligned(16)))
#endif
#else
#include <wmmintrin.h>
#include <sys/mman.h>
#define STATIC static
#define INLINE inline
#if !defined(RDATA_ALIGN16)
#define RDATA_ALIGN16 __attribute__((aligned(16)))
#endif
#endif

#if defined(__INTEL_COMPILER)
#define ASM __asm__
#elif !defined(_MSC_VER)
#define ASM __asm__
#else
#define ASM __asm
#endif

#define U64(x) ((uint64_t *)(x))
#define R128(x) ((__m128i *)(x))

#define state_index(x) (((*((uint64_t *)x) >> 4) & ((MEMORY / AES_BLOCK_SIZE) - 1)) << 4)
#if defined(_MSC_VER)
#if !defined(_WIN64)
#define __mul() lo = mul128(c[0], b[0], &hi);
#else
#define __mul() lo = _umul128(c[0], b[0], &hi);
#endif
#else
#if defined(__x86_64__)
#define __mul() ASM("mulq %3\n\t"            \
                    : "=d"(hi), "=a"(lo)     \
                    : "%a"(c[0]), "rm"(b[0]) \
                    : "cc");
#else
#define __mul() lo = mul128(c[0], b[0], &hi);
#endif
#endif

#define pre_aes()                            \
    j = state_index(a);                      \
    _c = _mm_load_si128(R128(&hp_state[j])); \
    _a = _mm_load_si128(R128(a));

#define post_aes_novariant()                 \
    _mm_store_si128(R128(c), _c);            \
    _b = _mm_xor_si128(_b, _c);              \
    _mm_store_si128(R128(&hp_state[j]), _b); \
    j = state_index(c);                      \
    p = U64(&hp_state[j]);                   \
    b[0] = p[0];                             \
    b[1] = p[1];                             \
    __mul();                                 \
    a[0] += hi;                              \
    a[1] += lo;                              \
    p = U64(&hp_state[j]);                   \
    p[0] = a[0];                             \
    p[1] = a[1];                             \
    a[0] ^= b[0];                            \
    a[1] ^= b[1];                            \
    _b = _c;

#define post_aes_variant()                   \
    _mm_store_si128(R128(c), _c);            \
    _b = _mm_xor_si128(_b, _c);              \
    _mm_store_si128(R128(&hp_state[j]), _b); \
    VARIANT1_1(&hp_state[j]);                \
    j = state_index(c);                      \
    p = U64(&hp_state[j]);                   \
    b[0] = p[0];                             \
    b[1] = p[1];                             \
    __mul();                                 \
    a[0] += hi;                              \
    a[1] += lo;                              \
    p = U64(&hp_state[j]);                   \
    p[0] = a[0];                             \
    p[1] = a[1];                             \
    a[0] ^= b[0];                            \
    a[1] ^= b[1];                            \
    VARIANT1_2(p + 1);                       \
    _b = _c;

#define init_hash()                                                             \
    uint32_t init_size_byte = (init_size_blk * AES_BLOCK_SIZE);                 \
    RDATA_ALIGN16 uint8_t expandedKey[240];                                     \
    uint8_t *text = (uint8_t *)malloc(init_size_byte);                          \
    RDATA_ALIGN16 uint64_t a[2];                                                \
    RDATA_ALIGN16 uint64_t b[4];                                                \
    RDATA_ALIGN16 uint64_t c[2];                                                \
    union cn_slow_hash_state state;                                             \
    __m128i _a, _b, _c;                                                         \
    uint64_t hi, lo;                                                            \
    size_t i, j;                                                                \
    uint64_t *p = NULL;                                                         \
    static void (*const extra_hashes[4])(const void *, size_t, char *) = {      \
        hash_extra_blake, hash_extra_groestl, hash_extra_jh, hash_extra_skein}; \
    slow_hash_allocate_state(); 

#define xor_u64()                                            \
    U64(a)[0] = U64(&state.k[0])[0] ^ U64(&state.k[32])[0];  \
    U64(a)[1] = U64(&state.k[0])[1] ^ U64(&state.k[32])[1];  \
    U64(b)[0] = U64(&state.k[16])[0] ^ U64(&state.k[48])[0]; \
    U64(b)[1] = U64(&state.k[16])[1] ^ U64(&state.k[48])[1];

#define expand_key()                                                                   \
    hash_process(&state.hs, data, length);                                             \
    memcpy(text, state.init, init_size_byte);                                          \
    const uint64_t tweak1_2 = (state.hs.w[24] ^ (*((const uint64_t *)NONCE_POINTER))); \
    aes_expand_key(state.hs.b, expandedKey);                                           \
    for (i = 0; i < MEMORY / init_size_byte; i++)                                      \
    {                                                                                  \
        aes_pseudo_round(text, text, expandedKey, init_size_blk);                      \
        memcpy(&hp_state[i * init_size_byte], text, init_size_byte);                   \
    }

#define finalize_hash()                                                                              \
    memcpy(text, state.init, init_size_byte);                                                        \
    aes_expand_key(&state.hs.b[32], expandedKey);                                                    \
    for (i = 0; i < MEMORY / init_size_byte; i++)                                                    \
    {                                                                                                \
        aes_pseudo_round_xor(text, text, expandedKey, &hp_state[i * init_size_byte], init_size_blk); \
    }                                                                                                \
    memcpy(state.init, text, init_size_byte);                                                        \
    hash_permutation(&state.hs);                                                                     \
    extra_hashes[state.hs.b[0] & 3](&state, 200, hash);                                              \
    free(text);

#if defined(_MSC_VER)
#define cpuid(info, x) __cpuidex(info, x, 0)
#else
void cpuid(int CPUInfo[4], int InfoType)
{
    ASM __volatile__(
        "cpuid"
        : "=a"(CPUInfo[0]),
          "=b"(CPUInfo[1]),
          "=c"(CPUInfo[2]),
          "=d"(CPUInfo[3])
        : "a"(InfoType), "c"(0));
}
#endif

STATIC INLINE void xor_blocks(uint8_t *a, const uint8_t *b)
{
    U64(a)[0] ^= U64(b)[0];
    U64(a)[1] ^= U64(b)[1];
}

STATIC INLINE void xor64(uint64_t *a, const uint64_t b)
{
    *a ^= b;
}

STATIC INLINE void aes_256_assist1(__m128i *t1, __m128i *t2)
{
    __m128i t4;
    *t2 = _mm_shuffle_epi32(*t2, 0xff);
    t4 = _mm_slli_si128(*t1, 0x04);
    *t1 = _mm_xor_si128(*t1, t4);
    t4 = _mm_slli_si128(t4, 0x04);
    *t1 = _mm_xor_si128(*t1, t4);
    t4 = _mm_slli_si128(t4, 0x04);
    *t1 = _mm_xor_si128(*t1, t4);
    *t1 = _mm_xor_si128(*t1, *t2);
}

STATIC INLINE void aes_256_assist2(__m128i *t1, __m128i *t3)
{
    __m128i t2, t4;
    t4 = _mm_aeskeygenassist_si128(*t1, 0x00);
    t2 = _mm_shuffle_epi32(t4, 0xaa);
    t4 = _mm_slli_si128(*t3, 0x04);
    *t3 = _mm_xor_si128(*t3, t4);
    t4 = _mm_slli_si128(t4, 0x04);
    *t3 = _mm_xor_si128(*t3, t4);
    t4 = _mm_slli_si128(t4, 0x04);
    *t3 = _mm_xor_si128(*t3, t4);
    *t3 = _mm_xor_si128(*t3, t2);
}

STATIC INLINE void aes_expand_key(const uint8_t *key, uint8_t *expandedKey)
{
    __m128i *ek = R128(expandedKey);
    __m128i t1, t2, t3;

    t1 = _mm_loadu_si128(R128(key));
    t3 = _mm_loadu_si128(R128(key + 16));

    ek[0] = t1;
    ek[1] = t3;

    t2 = _mm_aeskeygenassist_si128(t3, 0x01);
    aes_256_assist1(&t1, &t2);
    ek[2] = t1;
    aes_256_assist2(&t1, &t3);
    ek[3] = t3;

    t2 = _mm_aeskeygenassist_si128(t3, 0x02);
    aes_256_assist1(&t1, &t2);
    ek[4] = t1;
    aes_256_assist2(&t1, &t3);
    ek[5] = t3;

    t2 = _mm_aeskeygenassist_si128(t3, 0x04);
    aes_256_assist1(&t1, &t2);
    ek[6] = t1;
    aes_256_assist2(&t1, &t3);
    ek[7] = t3;

    t2 = _mm_aeskeygenassist_si128(t3, 0x08);
    aes_256_assist1(&t1, &t2);
    ek[8] = t1;
    aes_256_assist2(&t1, &t3);
    ek[9] = t3;

    t2 = _mm_aeskeygenassist_si128(t3, 0x10);
    aes_256_assist1(&t1, &t2);
    ek[10] = t1;
}

STATIC INLINE void aes_pseudo_round(const uint8_t *in, uint8_t *out, const uint8_t *expandedKey, int nblocks)
{
    __m128i *k = R128(expandedKey);
    __m128i d;
    int i;

    for (i = 0; i < nblocks; i++)
    {
        d = _mm_loadu_si128(R128(in + i * AES_BLOCK_SIZE));
        d = _mm_aesenc_si128(d, *R128(&k[0]));
        d = _mm_aesenc_si128(d, *R128(&k[1]));
        d = _mm_aesenc_si128(d, *R128(&k[2]));
        d = _mm_aesenc_si128(d, *R128(&k[3]));
        d = _mm_aesenc_si128(d, *R128(&k[4]));
        d = _mm_aesenc_si128(d, *R128(&k[5]));
        d = _mm_aesenc_si128(d, *R128(&k[6]));
        d = _mm_aesenc_si128(d, *R128(&k[7]));
        d = _mm_aesenc_si128(d, *R128(&k[8]));
        d = _mm_aesenc_si128(d, *R128(&k[9]));
        _mm_storeu_si128((R128(out + i * AES_BLOCK_SIZE)), d);
    }
}

STATIC INLINE void aes_pseudo_round_xor(const uint8_t *in, uint8_t *out, const uint8_t *expandedKey, const uint8_t *xo, int nblocks)
{
    __m128i *k = R128(expandedKey);
    __m128i *x = R128(xo);
    __m128i d;
    int i;

    for (i = 0; i < nblocks; i++)
    {
        d = _mm_loadu_si128(R128(in + i * AES_BLOCK_SIZE));
        d = _mm_xor_si128(d, *R128(x++));
        d = _mm_aesenc_si128(d, *R128(&k[0]));
        d = _mm_aesenc_si128(d, *R128(&k[1]));
        d = _mm_aesenc_si128(d, *R128(&k[2]));
        d = _mm_aesenc_si128(d, *R128(&k[3]));
        d = _mm_aesenc_si128(d, *R128(&k[4]));
        d = _mm_aesenc_si128(d, *R128(&k[5]));
        d = _mm_aesenc_si128(d, *R128(&k[6]));
        d = _mm_aesenc_si128(d, *R128(&k[7]));
        d = _mm_aesenc_si128(d, *R128(&k[8]));
        d = _mm_aesenc_si128(d, *R128(&k[9]));
        _mm_storeu_si128((R128(out + i * AES_BLOCK_SIZE)), d);
    }
}

#if defined(_MSC_VER) || defined(__MINGW32__)
BOOL SetLockPagesPrivilege(HANDLE hProcess, BOOL bEnable)
{
    struct
    {
        DWORD count;
        LUID_AND_ATTRIBUTES privilege[1];
    } info;

    HANDLE token;
    if (!OpenProcessToken(hProcess, TOKEN_ADJUST_PRIVILEGES, &token))
        return FALSE;

    info.count = 1;
    info.privilege[0].Attributes = bEnable ? SE_PRIVILEGE_ENABLED : 0;

    if (!LookupPrivilegeValue(NULL, SE_LOCK_MEMORY_NAME, &(info.privilege[0].Luid)))
        return FALSE;

    if (!AdjustTokenPrivileges(token, FALSE, (PTOKEN_PRIVILEGES)&info, 0, NULL, NULL))
        return FALSE;

    if (GetLastError() != ERROR_SUCCESS)
        return FALSE;

    CloseHandle(token);

    return TRUE;
}
#endif

#else

static void (*const extra_hashes[4])(const void *, size_t, char *) = {
    hash_extra_blake, hash_extra_groestl, hash_extra_jh, hash_extra_skein};

static size_t e2i(const uint8_t *a, size_t count) { return (*((uint64_t *)a) / AES_BLOCK_SIZE) & (count - 1); }

static void mul(const uint8_t *a, const uint8_t *b, uint8_t *res)
{
    uint64_t a0, b0;
    uint64_t hi, lo;

    a0 = SWAP64LE(((uint64_t *)a)[0]);
    b0 = SWAP64LE(((uint64_t *)b)[0]);
    lo = mul128(a0, b0, &hi);
    ((uint64_t *)res)[0] = SWAP64LE(hi);
    ((uint64_t *)res)[1] = SWAP64LE(lo);
}

static void sum_half_blocks(uint8_t *a, const uint8_t *b)
{
    uint64_t a0, a1, b0, b1;

    a0 = SWAP64LE(((uint64_t *)a)[0]);
    a1 = SWAP64LE(((uint64_t *)a)[1]);
    b0 = SWAP64LE(((uint64_t *)b)[0]);
    b1 = SWAP64LE(((uint64_t *)b)[1]);
    a0 += b0;
    a1 += b1;
    ((uint64_t *)a)[0] = SWAP64LE(a0);
    ((uint64_t *)a)[1] = SWAP64LE(a1);
}

#define U64(x) ((uint64_t *)(x))

static void copy_block(uint8_t *dst, const uint8_t *src)
{
    memcpy(dst, src, AES_BLOCK_SIZE);
}

static void swap_blocks(uint8_t *a, uint8_t *b)
{
    uint64_t t[2];
    U64(t)[0] = U64(a)[0];
    U64(t)[1] = U64(a)[1];
    U64(a)[0] = U64(b)[0];
    U64(a)[1] = U64(b)[1];
    U64(b)[0] = U64(t)[0];
    U64(b)[1] = U64(t)[1];
}

static void xor_blocks(uint8_t *a, const uint8_t *b)
{
    size_t i;
    for (i = 0; i < AES_BLOCK_SIZE; i++)
        a[i] ^= b[i];
}

static void xor64(uint8_t *left, const uint8_t *right)
{
    size_t i;
    for (i = 0; i < 8; ++i)
        left[i] ^= right[i];
}

#define VARIANT1_1(p)                                          \
    const uint8_t tmp = ((const uint8_t *)(p))[11];            \
    static const uint32_t table = 0x75310;                     \
    const uint8_t index = (((tmp >> 3) & 6) | (tmp & 1)) << 1; \
    ((uint8_t *)(p))[11] = tmp ^ ((table >> index) & 0x30);

#define VARIANT1_2(p) \
    xor64(p, tweak1_2);

#define aes_sw_variant()                                   \
    j = e2i(a, MEMORY / AES_BLOCK_SIZE) * AES_BLOCK_SIZE;  \
    copy_block(c1, &hp_state[j]);                          \
    aesb_single_round(c1, c1, a);                          \
    copy_block(&hp_state[j], c1);                          \
    xor_blocks(&hp_state[j], b);                           \
    VARIANT1_1(&hp_state[j]);                              \
    j = e2i(c1, MEMORY / AES_BLOCK_SIZE) * AES_BLOCK_SIZE; \
    copy_block(c2, &hp_state[j]);                          \
    mul(c1, c2, d);                                        \
    swap_blocks(a, c1);                                    \
    sum_half_blocks(c1, d);                                \
    swap_blocks(c1, c2);                                   \
    xor_blocks(c1, c2);                                    \
    VARIANT1_2(c2 + 8);                                    \
    copy_block(&hp_state[j], c2);                          \
    copy_block(b, a);                                      \
    copy_block(a, c1);

#define aes_sw_novariant()                                 \
    j = e2i(a, MEMORY / AES_BLOCK_SIZE) * AES_BLOCK_SIZE;  \
    copy_block(c1, &hp_state[j]);                          \
    aesb_single_round(c1, c1, a);                          \
    copy_block(&hp_state[j], c1);                          \
    xor_blocks(&hp_state[j], b);                           \
    j = e2i(c1, MEMORY / AES_BLOCK_SIZE) * AES_BLOCK_SIZE; \
    copy_block(c2, &hp_state[j]);                          \
    mul(c1, c2, d);                                        \
    swap_blocks(a, c1);                                    \
    sum_half_blocks(c1, d);                                \
    swap_blocks(c1, c2);                                   \
    xor_blocks(c1, c2);                                    \
    copy_block(&hp_state[j], c2);                          \
    copy_block(b, a);                                      \
    copy_block(a, c1);

#define init_hash()                                                \
    union cn_slow_hash_state state;                                \
    uint32_t init_size_byte = (init_size_blk * AES_BLOCK_SIZE);    \
    uint8_t *text = (uint8_t *)malloc(init_size_byte);             \
    uint8_t a[AES_BLOCK_SIZE];                                     \
    uint8_t b[AES_BLOCK_SIZE];                                     \
    uint8_t c1[AES_BLOCK_SIZE];                                    \
    uint8_t c2[AES_BLOCK_SIZE];                                    \
    uint8_t d[AES_BLOCK_SIZE];                                     \
    size_t i, j;                                                   \
    uint8_t aes_key[AES_KEY_SIZE];                                 \
    oaes_ctx *aes_ctx;                                             \
    slow_hash_allocate_state();

#define expand_key()                                                                                         \
    hash_process(&state.hs, data, length);                                                                   \
    memcpy(text, state.init, init_size_byte);                                                                \
    memcpy(aes_key, state.hs.b, AES_KEY_SIZE);                                                               \
    aes_ctx = (oaes_ctx *)oaes_alloc();                                                                      \
    uint8_t tweak1_2[8];                                                                                     \
    memcpy(&tweak1_2, &state.hs.b[192], sizeof(tweak1_2));                                                   \
    xor64(tweak1_2, NONCE_POINTER);                                                                          \
    oaes_key_import_data(aes_ctx, aes_key, AES_KEY_SIZE);                                                    \
    for (i = 0; i < MEMORY / init_size_byte; i++)                                                            \
    {                                                                                                        \
        for (j = 0; j < init_size_blk; j++)                                                                  \
        {                                                                                                    \
            aesb_pseudo_round(&text[AES_BLOCK_SIZE * j], &text[AES_BLOCK_SIZE * j], aes_ctx->key->exp_data); \
        }                                                                                                    \
        memcpy(&hp_state[i * init_size_byte], text, init_size_byte);                                         \
    }

#define finalize_hash()                                                                                      \
    memcpy(text, state.init, init_size_byte);                                                                \
    oaes_key_import_data(aes_ctx, &state.hs.b[32], AES_KEY_SIZE);                                            \
    for (i = 0; i < MEMORY / init_size_byte; i++)                                                            \
    {                                                                                                        \
        for (j = 0; j < init_size_blk; j++)                                                                  \
        {                                                                                                    \
            xor_blocks(&text[j * AES_BLOCK_SIZE], &hp_state[i * init_size_byte + j * AES_BLOCK_SIZE]);       \
            aesb_pseudo_round(&text[AES_BLOCK_SIZE * j], &text[AES_BLOCK_SIZE * j], aes_ctx->key->exp_data); \
        }                                                                                                    \
    }                                                                                                        \
    memcpy(state.init, text, init_size_byte);                                                                \
    hash_permutation(&state.hs);                                                                             \
    extra_hashes[state.hs.b[0] & 3](&state, 200, hash);                                                      \
    oaes_free((OAES_CTX **)&aes_ctx);                                                                        \
    free(text);                                                                                              

#define xor_u64()                                                             \
    for (i = 0; i < AES_BLOCK_SIZE; i++)                                      \
    {                                                                         \
        a[i] = state.k[i] ^ state.k[AES_BLOCK_SIZE * 2 + i];                  \
        b[i] = state.k[AES_BLOCK_SIZE + i] ^ state.k[AES_BLOCK_SIZE * 3 + i]; \
    }

#endif

void slow_hash_allocate_state(void);
void slow_hash_free_state(void);

#define salt_pad(a, b, c, d)                           \
    extra_hashes[a % 3](sp_bytes, 200, salt_hash);     \
    temp_1 = (uint16_t)(iters ^ (b ^ c));              \
    offset_1 = temp_1 * ((d % 3) + 1);                 \
    for (j = 0; j < 32; j++)                           \
        sp_bytes[offset_1 + j] ^= salt_hash[j];        \
    x = 0;                                             \
    offset_1 = (d % 64) + 1;                           \
    offset_2 = ((temp_1 * offset_1) % 125) + 4;        \
    for (j = offset_1; j < MEMORY; j += offset_2)      \
        hp_state[j] ^= sp_bytes[x++];

#define randomize_scratchpad(r, scratchpad)            \
    for (int i = 0; i < RANDOM_VALUES; i++)            \
    {                                                  \
        switch (r->operators[i])                       \
        {                                              \
        case ADD:                                      \
            scratchpad[r->indices[i]] += r->values[i]; \
            break;                                     \
        case SUB:                                      \
            scratchpad[r->indices[i]] -= r->values[i]; \
            break;                                     \
        case XOR:                                      \
            scratchpad[r->indices[i]] ^= r->values[i]; \
            break;                                     \
        case OR:                                       \
            scratchpad[r->indices[i]] |= r->values[i]; \
            break;                                     \
        case AND:                                      \
            scratchpad[r->indices[i]] &= r->values[i]; \
            break;                                     \
        case COMP:                                     \
            scratchpad[r->indices[i]] = ~r->values[i]; \
            break;                                     \
        case EQ:                                       \
            scratchpad[r->indices[i]] = r->values[i];  \
            break;                                     \
        }                                              \
    }

#define randomize_scratchpad_256k(r, salt, scratchpad) \
    uint32_t x = 0;                                    \
    for (uint32_t i = 0; i < MEMORY; i += 4)           \
        scratchpad[i] ^= salt[x++];                    \
    randomize_scratchpad(r, scratchpad);

#define randomize_scratchpad_4k(r, salt, scratchpad)   \
    uint32_t x = 0;                                    \
    for (uint32_t i = 0; i < MEMORY; i += 256)         \
        scratchpad[i] ^= salt[x++];                    \
    randomize_scratchpad(r, scratchpad);

#endif
