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

#include "hash-ops.h"
#include "slow-hash.h"

#pragma pack(push, 1)
union cn_slow_hash_state {
    union hash_state hs;
    struct
    {
        uint8_t k[64];
        uint8_t init[128];
    };
};
#pragma pack(pop)

#if !defined NO_AES && (defined(__x86_64__) || (defined(_MSC_VER) && defined(_WIN64)))

THREADV uint8_t *hp_state = NULL;
THREADV char *salt_state = NULL;
THREADV int hp_allocated = 0;
THREADV int salt_allocated = 0;

void allocate_scratchpad(void)
{
    if (hp_state != NULL)
        return;

#if defined(_MSC_VER) || defined(__MINGW32__)
    SetLockPagesPrivilege(GetCurrentProcess(), TRUE);
    hp_state = (uint8_t *)VirtualAlloc(hp_state, MEMORY, MEM_LARGE_PAGES | MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
#else
#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__DragonFly__) || defined(__NetBSD__)
    hp_state = mmap(0, MEMORY, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, 0, 0);
#else
    hp_state = mmap(0, MEMORY, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB, 0, 0);
#endif
    if (hp_state == MAP_FAILED)
        hp_state = NULL;
#endif
    hp_allocated = 1;
    if (hp_state == NULL)
    {
        hp_allocated = 0;
        hp_state = (uint8_t *)malloc(MEMORY);
    }
}

void allocate_salt(void)
{
    if (salt_state != NULL)
        return;

#if defined(_MSC_VER) || defined(__MINGW32__)
    SetLockPagesPrivilege(GetCurrentProcess(), TRUE);
    salt_state = (char*)VirtualAlloc(salt_state, SALT_MEMORY, MEM_LARGE_PAGES | MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
#else
#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__DragonFly__) || defined(__NetBSD__)
    salt_state = mmap(0, SALT_MEMORY, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, 0, 0);
#else
    salt_state = mmap(0, SALT_MEMORY, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB, 0, 0);
#endif
    if (salt_state == MAP_FAILED)
        salt_state = NULL;
#endif
    salt_allocated = 1;
    if (salt_state == NULL)
    {
        salt_allocated = 0;
        salt_state = (char *)malloc(SALT_MEMORY);
    }
}

void slow_hash_allocate_state(void)
{
    allocate_scratchpad();
    allocate_salt();
}

void free_scratchpad(void)
{
    if (hp_state == NULL)
        return;

    if (!hp_allocated)
        free(hp_state);
    else
    {
#if defined(_MSC_VER) || defined(__MINGW32__)
        VirtualFree(hp_state, 0, MEM_RELEASE);
#else
        munmap(hp_state, MEMORY);
#endif
    }
    hp_state = NULL;
    hp_allocated = 0;
}

void free_salt(void)
{
    if (salt_state == NULL)
        return;

    if (!salt_allocated)
        free(salt_state);
    else
    {
#if defined(_MSC_VER) || defined(__MINGW32__)
        VirtualFree(salt_state, 0, MEM_RELEASE);
#else
        munmap(salt_state, SALT_MEMORY);
#endif
    }
    salt_state = NULL;
    salt_allocated = 0;
}

void slow_hash_free_state(void)
{
    free_scratchpad();
    free_salt();
}

char* get_salt_state(void)
{
    return salt_state;
}

void cn_slow_hash_v11(const void *data, size_t length, char *hash, size_t iters, random_values *r, char *sp_bytes, uint8_t init_size_blk, uint16_t xx, uint16_t yy)
{
    char salt_hash[32];
    init_hash();
    expand_key();
    randomize_scratchpad_256k(r, sp_bytes, hp_state);
    xor_u64();

    _b = _mm_load_si128(R128(b));

    uint16_t temp_1 = 0;
    uint32_t offset_1 = 0;
    uint32_t offset_2 = 0;

    uint16_t k = 1, l = 1;
    uint16_t *r2 = (uint16_t *)&c;
    for (k = 1; k < xx; k++)
    {
        pre_aes();
        _c = _mm_aesenc_si128(_c, _a);
        post_aes_variant();
        salt_pad(r2[0], r2[2], r2[4], r2[6]);

        for (l = 1; l < yy; l++)
        {
            pre_aes();
            _c = _mm_aesenc_si128(_c, _a);
            post_aes_variant();
            salt_pad(r2[1], r2[3], r2[5], r2[7]);
        }
    }

    for (i = 0; i < iters; i++)
    {
        pre_aes();
        _c = _mm_aesenc_si128(_c, _a);
        post_aes_variant();
    }

    finalize_hash();
}

void cn_slow_hash_v10(const void *data, size_t length, char *hash, size_t iters, random_values *r, char *sp_bytes, uint8_t init_size_blk, uint16_t xx, uint16_t yy, uint16_t zz, uint16_t ww)
{
    char *salt_hash = (char *)malloc(32);

    init_hash();
    expand_key();
    randomize_scratchpad_256k(r, sp_bytes, hp_state);
    xor_u64();

    _b = _mm_load_si128(R128(b));

    uint16_t temp_1 = 0;
    uint32_t offset_1 = 0;
    uint32_t offset_2 = 0;

    uint16_t r2[6] = {xx ^ yy, xx ^ zz, xx ^ ww, yy ^ zz, yy ^ ww, zz ^ ww};
    uint16_t k = 1, l = 1, m = 1;

    for (k = 1; k < xx; k++)
    {
        r2[0] ^= r2[1];
        r2[1] ^= r2[2];
        r2[2] ^= r2[3];
        r2[3] ^= r2[4];
        r2[4] ^= r2[5];
        r2[5] ^= r2[0];

        pre_aes();
        _c = _mm_aesenc_si128(_c, _a);
        post_aes_variant();
        salt_pad(r2[0], r2[3], r2[1], r2[4]);
        r2[0] ^= (r2[1] ^ r2[3]);
        r2[1] ^= (r2[0] ^ r2[2]);

        for (l = 1; l < yy; l++)
        {
            pre_aes();
            _c = _mm_aesenc_si128(_c, _a);
            post_aes_variant();
            salt_pad(r2[1], r2[4], r2[2], r2[5]);
            r2[2] ^= (r2[3] ^ r2[5]);
            r2[3] ^= (r2[2] ^ r2[4]);

            for (m = 1; m < zz; m++)
            {
                pre_aes();
                _c = _mm_aesenc_si128(_c, _a);
                post_aes_variant();
                salt_pad(r2[2], r2[5], r2[3], r2[0]);
                r2[4] ^= (r2[5] ^ r2[1]);
                r2[5] ^= (r2[4] ^ r2[0]);
            }
        }
    }

    for (i = 0; i < iters; i++)
    {
        pre_aes();
        _c = _mm_aesenc_si128(_c, _a);
        post_aes_variant();
    }

    finalize_hash();
    free(salt_hash);
}

void cn_slow_hash_v9(const void *data, size_t length, char *hash, size_t iters, random_values *r, char* sp_bytes)
{
    uint32_t init_size_blk = INIT_SIZE_BLK;
    init_hash();
    expand_key();
    randomize_scratchpad_4k(r, sp_bytes, hp_state);
    xor_u64();

    _b = _mm_load_si128(R128(b));

    for(i = 0; i < iters; i++)
    {
        pre_aes();
        _c = _mm_aesenc_si128(_c, _a);
        post_aes_variant();
    }

    finalize_hash();
}

void cn_slow_hash_v7_8(const void *data, size_t length, char *hash, size_t iters, random_values *r)
{
    uint32_t init_size_blk = INIT_SIZE_BLK;
    init_hash();
    expand_key();
    randomize_scratchpad(r, hp_state);
    xor_u64();

    _b = _mm_load_si128(R128(b));

    for (i = 0; i < iters; i++)
    {
        pre_aes();
        _c = _mm_aesenc_si128(_c, _a);
        post_aes_variant();
    }

    finalize_hash();
}

void cn_slow_hash(const void *data, size_t length, char *hash, int variant, int prehashed, size_t iters)
{ 
    uint32_t init_size_blk = INIT_SIZE_BLK;
    init_hash();

    if (prehashed)
        memcpy(&state.hs, data, length);
    else
        hash_process(&state.hs, data, length);

    memcpy(text, state.init, init_size_byte);
    const uint64_t tweak1_2 = variant > 0 ? (state.hs.w[24] ^ (*((const uint64_t *)NONCE_POINTER))) : 0;

    aes_expand_key(state.hs.b, expandedKey);
    for(i = 0; i < MEMORY / init_size_byte; i++)
    {
        aes_pseudo_round(text, text, expandedKey, INIT_SIZE_BLK);
        memcpy(&hp_state[i * init_size_byte], text, init_size_byte);
    }

    xor_u64();

    _b = _mm_load_si128(R128(b));

    if (variant > 0)
    {
        for(i = 0; i < iters; i++)
        {
            pre_aes();
            _c = _mm_aesenc_si128(_c, _a);
            post_aes_variant();
        }
    }
    else
    {
        for(i = 0; i < iters; i++)
        {
            pre_aes();
            _c = _mm_aesenc_si128(_c, _a);
            post_aes_novariant();
        }   
    }

    finalize_hash();
}

#else

THREADV uint8_t *hp_state = NULL;
THREADV char *salt_state = NULL;

void slow_hash_allocate_state(void)
{
    hp_state = (uint8_t *)malloc(MEMORY);
    salt_state = (char *)malloc(SALT_MEMORY);
}

void slow_hash_free_state(void)
{ 
    free(hp_state);
    free(salt_state);
}

char* get_salt_state(void)
{
    return salt_state;
}

void cn_slow_hash_v11(const void *data, size_t length, char *hash, size_t iters, random_values *r, char *sp_bytes, uint8_t init_size_blk, uint16_t xx, uint16_t yy)
{
    char salt_hash[32];
    init_hash();
    expand_key();
    randomize_scratchpad_256k(r, sp_bytes, hp_state);
    xor_u64();

    uint16_t temp_1 = 0;
    uint32_t offset_1 = 0;
    uint32_t offset_2 = 0;

    uint16_t k = 1, l = 1;
    uint16_t *r2 = (uint16_t *)&c1;
    for (k = 1; k < xx; k++)
    {
        aes_sw_variant();
        salt_pad(r2[0], r2[2], r2[4], r2[6]);

        for (l = 1; l < yy; l++)
        {
            aes_sw_variant();
            salt_pad(r2[1], r2[3], r2[5], r2[7]);
        }
    }

    for (i = 0; i < iters; i++)
        aes_sw_variant();

    finalize_hash();
    free(salt_hash);
}

void cn_slow_hash_v10(const void *data, size_t length, char *hash, size_t iters, random_values *r, char *sp_bytes, uint8_t init_size_blk, uint16_t xx, uint16_t yy, uint16_t zz, uint16_t ww)
{
    char *salt_hash = (char *)malloc(32);
    init_hash();
    expand_key();
    randomize_scratchpad_256k(r, sp_bytes, hp_state);
    xor_u64();

    uint16_t temp_1 = 0;
    uint32_t offset_1 = 0;
    uint32_t offset_2 = 0;

    uint16_t r2[6] = {xx ^ yy, xx ^ zz, xx ^ ww, yy ^ zz, yy ^ ww, zz ^ ww};
    uint16_t k = 1, l = 1, m = 1;

    for (k = 1; k < xx; k++)
    {
        r2[0] ^= r2[1];
        r2[1] ^= r2[2];
        r2[2] ^= r2[3];
        r2[3] ^= r2[4];
        r2[4] ^= r2[5];
        r2[5] ^= r2[0];

        aes_sw_variant();
        salt_pad(r2[0], r2[3], r2[1], r2[4]);
        r2[0] ^= (r2[1] ^ r2[3]);
        r2[1] ^= (r2[0] ^ r2[2]);

        for (l = 1; l < yy; l++)
        {
            aes_sw_variant();
            salt_pad(r2[1], r2[4], r2[2], r2[5]);
            r2[2] ^= (r2[3] ^ r2[5]);
            r2[3] ^= (r2[2] ^ r2[4]);

            for (m = 1; m < zz; m++)
            {
                aes_sw_variant();
                salt_pad(r2[2], r2[5], r2[3], r2[0]);
                r2[4] ^= (r2[5] ^ r2[1]);
                r2[5] ^= (r2[4] ^ r2[0]);
            }
        }
    }

    for (i = 0; i < iters; i++) {
        aes_sw_variant();
    }

    finalize_hash();
    free(salt_hash);
}

void cn_slow_hash_v9(const void *data, size_t length, char *hash, size_t iters, random_values *r, char *sp_bytes)
{
    uint32_t init_size_blk = INIT_SIZE_BLK;
    char *salt_hash = (char *)malloc(32);
    init_hash();
    expand_key();
    randomize_scratchpad_4k(r, sp_bytes, hp_state);
    xor_u64();

    for (i = 0; i < iters; i++) {
        aes_sw_variant();
    }

    finalize_hash();
    free(salt_hash);
}

void cn_slow_hash_v7_8(const void *data, size_t length, char *hash, size_t iters, random_values *r)
{
    uint32_t init_size_blk = INIT_SIZE_BLK;
    init_hash();
    expand_key();
    randomize_scratchpad(r, hp_state);
    xor_u64();

    for (i = 0; i < iters; i++) {
        aes_sw_variant();
    }

    finalize_hash();
}

void cn_slow_hash(const void *data, size_t length, char *hash, int variant, int prehashed, size_t iters)
{
    uint32_t init_size_blk = INIT_SIZE_BLK;
    init_hash();

    if (prehashed)
        memcpy(&state.hs, data, length);
    else
        hash_process(&state.hs, data, length);
    
    memcpy(text, state.init, init_size_byte);
    memcpy(aes_key, state.hs.b, AES_KEY_SIZE);
    aes_ctx = (oaes_ctx *) oaes_alloc();

    uint8_t tweak1_2[8] = {0};
    if (variant > 0)
    {
        memcpy(&tweak1_2, &state.hs.b[192], sizeof(tweak1_2));
        xor64(tweak1_2, NONCE_POINTER);
    }

    oaes_key_import_data(aes_ctx, aes_key, AES_KEY_SIZE);
    for (i = 0; i < MEMORY / init_size_byte; i++) {
        for (j = 0; j < INIT_SIZE_BLK; j++) {
            aesb_pseudo_round(&text[AES_BLOCK_SIZE * j], &text[AES_BLOCK_SIZE * j], aes_ctx->key->exp_data);
        }
        memcpy(&hp_state[i * init_size_byte], text, init_size_byte);
    }

    xor_u64();

    if (variant > 0) {
        for (i = 0; i < iters; i++) {
            aes_sw_variant();
        }
    } else {
        for (i = 0; i < iters; i++) {
            aes_sw_novariant();
        }
    }

    finalize_hash();
}

#endif
