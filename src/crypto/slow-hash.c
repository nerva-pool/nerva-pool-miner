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


#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <math.h>

#include "common/int-util.h"
#include "hash-ops.h"
#include "oaes_lib.h"

#define AES_BLOCK_SIZE  16
#define AES_KEY_SIZE    32
extern void aesb_single_round(const uint8_t *in, uint8_t *out, const uint8_t *expandedKey);
extern void aesb_pseudo_round(const uint8_t *in, uint8_t *out, const uint8_t *expandedKey);

#define VARIANT1_1(p) \
  do if (variant > 0) \
  { \
    const uint8_t tmp = ((const uint8_t*)(p))[11]; \
    static const uint32_t table = 0x75310; \
    const uint8_t index = (((tmp >> 3) & 6) | (tmp & 1)) << 1; \
    ((uint8_t*)(p))[11] = tmp ^ ((table >> index) & 0x30); \
  } while(0)

#define VARIANT1_2(p) \
  do if (variant > 0) \
  { \
    xor64(p, tweak1_2); \
  } while(0)

#define VARIANT2_INIT64() \
  do if (variant >= 2) \
  { \
    U64(b)[2] = state.hs.w[8] ^ state.hs.w[10]; \
    U64(b)[3] = state.hs.w[9] ^ state.hs.w[11]; \
  } while (0)

#define VARIANT2_PORTABLE_INIT() \
  do if (variant >= 2) \
  { \
    memcpy(b + AES_BLOCK_SIZE, state.hs.b + 64, AES_BLOCK_SIZE); \
    xor64(b + AES_BLOCK_SIZE, state.hs.b + 80); \
    xor64(b + AES_BLOCK_SIZE + 8, state.hs.b + 88); \
  } while (0)

#define VARIANT2_2() \
  do if (variant >= 2) \
  { \
    *U64(hp_state + (j ^ 0x10)) ^= hi; \
    *(U64(hp_state + (j ^ 0x10)) + 1) ^= lo; \
    hi ^= *U64(hp_state + (j ^ 0x20)); \
    lo ^= *(U64(hp_state + (j ^ 0x20)) + 1); \
  } while (0)

#define VARIANT2_2_PORTABLE() \
  if (variant >= 2) { \
    xor_blocks(long_state + (j ^ 0x10), d); \
    xor_blocks(d, long_state + (j ^ 0x20)); \
  }

#define VARIANT2_SHUFFLE_ADD_SSE2(base_ptr, offset) \
  do if (variant >= 2) \
  { \
    const __m128i chunk1 = _mm_load_si128((__m128i *)((base_ptr) + ((offset) ^ 0x10))); \
    const __m128i chunk2 = _mm_load_si128((__m128i *)((base_ptr) + ((offset) ^ 0x20))); \
    const __m128i chunk3 = _mm_load_si128((__m128i *)((base_ptr) + ((offset) ^ 0x30))); \
    _mm_store_si128((__m128i *)((base_ptr) + ((offset) ^ 0x10)), _mm_add_epi64(chunk3, _b1)); \
    _mm_store_si128((__m128i *)((base_ptr) + ((offset) ^ 0x20)), _mm_add_epi64(chunk1, _b)); \
    _mm_store_si128((__m128i *)((base_ptr) + ((offset) ^ 0x30)), _mm_add_epi64(chunk2, _a)); \
  } while (0)

#define VARIANT2_PORTABLE_SHUFFLE_ADD(base_ptr, offset) \
  do if (variant >= 2) \
  { \
    uint64_t* chunk1 = U64((base_ptr) + ((offset) ^ 0x10)); \
    uint64_t* chunk2 = U64((base_ptr) + ((offset) ^ 0x20)); \
    uint64_t* chunk3 = U64((base_ptr) + ((offset) ^ 0x30)); \
    \
    const uint64_t chunk1_old[2] = { chunk1[0], chunk1[1] }; \
    \
    uint64_t b1[2]; \
    memcpy(b1, b + 16, 16); \
    chunk1[0] = chunk3[0] + b1[0]; \
    chunk1[1] = chunk3[1] + b1[1]; \
    \
    uint64_t a0[2]; \
    memcpy(a0, a, 16); \
    chunk3[0] = chunk2[0] + a0[0]; \
    chunk3[1] = chunk2[1] + a0[1]; \
    \
    uint64_t b0[2]; \
    memcpy(b0, b, 16); \
    chunk2[0] = chunk1_old[0] + b0[0]; \
    chunk2[1] = chunk1_old[1] + b0[1]; \
  } while (0)

#define VARIANT1_CHECK() \
  do if (length < 43) \
  { \
    fprintf(stderr, "Cryptonight variants need at least 43 bytes of data"); \
    _exit(1); \
  } while(0)

#define NONCE_POINTER (((const uint8_t*)data)+35)

#define VARIANT1_PORTABLE_INIT() \
  uint8_t tweak1_2[8]; \
  do if (variant > 0) \
  { \
    VARIANT1_CHECK(); \
    memcpy(&tweak1_2, &state.hs.b[192], sizeof(tweak1_2)); \
    xor64(tweak1_2, NONCE_POINTER); \
  } while(0)

#define VARIANT1_INIT64() \
  if (variant > 0) \
  { \
    VARIANT1_CHECK(); \
  } \
  const uint64_t tweak1_2 = variant > 0 ? (state.hs.w[24] ^ (*((const uint64_t*)NONCE_POINTER))) : 0

#if !defined NO_AES && (defined(__x86_64__) || (defined(_MSC_VER) && defined(_WIN64)))
// Optimised code below, uses x86-specific intrinsics, SSE2, AES-NI
// Fall back to more portable code is down at the bottom

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
#define RDATA_ALIGN16 __attribute__ ((aligned(16)))
#endif
#else
#include <wmmintrin.h>
#include <sys/mman.h>
#define STATIC static
#define INLINE inline
#if !defined(RDATA_ALIGN16)
#define RDATA_ALIGN16 __attribute__ ((aligned(16)))
#endif
#endif

#if defined(__INTEL_COMPILER)
#define ASM __asm__
#elif !defined(_MSC_VER)
#define ASM __asm__
#else
#define ASM __asm
#endif

#define U64(x) ((uint64_t *) (x))
#define R128(x) ((__m128i *) (x))

#define state_index(x) (((*((uint64_t *)x) >> 4) & ((memory / AES_BLOCK_SIZE) - 1)) << 4)
#if defined(_MSC_VER)
#if !defined(_WIN64)
#define __mul() lo = mul128(c[0], b[0], &hi);
#else
#define __mul() lo = _umul128(c[0], b[0], &hi);
#endif
#else
#if defined(__x86_64__)
#define __mul() ASM("mulq %3\n\t" : "=d"(hi), "=a"(lo) : "%a" (c[0]), "rm" (b[0]) : "cc");
#else
#define __mul() lo = mul128(c[0], b[0], &hi);
#endif
#endif

#define pre_aes() \
  j = state_index(a); \
  _c = _mm_load_si128(R128(&hp_state[j])); \
  _a = _mm_load_si128(R128(a)); \

#define post_aes(sh, v22) \
  _mm_store_si128(R128(c), _c); \
  _b = _mm_xor_si128(_b, _c); \
  _mm_store_si128(R128(&hp_state[j]), _b); \
  VARIANT1_1(&hp_state[j]); \
  j = state_index(c); \
  p = U64(&hp_state[j]); \
  b[0] = p[0]; b[1] = p[1]; \
  __mul(); \
  if (v22) \
      VARIANT2_2(); \
  if (sh) \
      VARIANT2_SHUFFLE_ADD_SSE2(hp_state, j); \
  a[0] += hi; a[1] += lo; \
  p = U64(&hp_state[j]); \
  p[0] = a[0];  p[1] = a[1]; \
  a[0] ^= b[0]; a[1] ^= b[1]; \
  VARIANT1_2(p + 1); \
  _b1 = _b; \
  _b = _c; \

#if defined(_MSC_VER)
#define THREADV __declspec(thread)
#else
#define THREADV __thread
#endif

#pragma pack(push, 1)
union cn_slow_hash_state
{
    union hash_state hs;
    struct
    {
        uint8_t k[64];
        uint8_t init[128];
    };
};
#pragma pack(pop)

THREADV uint8_t *hp_state = NULL;
THREADV int hp_allocated = 0;

#if defined(_MSC_VER)
#define cpuid(info,x)    __cpuidex(info,x,0)
#else
void cpuid(int CPUInfo[4], int InfoType)
{
    ASM __volatile__
    (
    "cpuid":
        "=a" (CPUInfo[0]),
        "=b" (CPUInfo[1]),
        "=c" (CPUInfo[2]),
        "=d" (CPUInfo[3]) :
            "a" (InfoType), "c" (0)
        );
}
#endif

/**
 * @brief a = (a xor b), where a and b point to 128 bit values
 */

STATIC INLINE void xor_blocks(uint8_t *a, const uint8_t *b)
{
    U64(a)[0] ^= U64(b)[0];
    U64(a)[1] ^= U64(b)[1];
}

STATIC INLINE void xor64(uint64_t *a, const uint64_t b)
{
    *a ^= b;
}

/**
 * @brief uses cpuid to determine if the CPU supports the AES instructions
 * @return true if the CPU supports AES, false otherwise
 */

STATIC INLINE int force_software_aes(void)
{
  static int use = -1;

  if (use != -1)
    return use;

  const char *env = getenv("MONERO_USE_SOFTWARE_AES");
  if (!env) {
    use = 0;
  }
  else if (!strcmp(env, "0") || !strcmp(env, "no")) {
    use = 0;
  }
  else {
    use = 1;
  }
  return use;
}

STATIC INLINE int check_aes_hw(void)
{
    int cpuid_results[4];
    static int supported = -1;

    if(supported >= 0)
        return supported;

    cpuid(cpuid_results,1);
    return supported = cpuid_results[2] & (1 << 25);
}

STATIC INLINE void aes_256_assist1(__m128i* t1, __m128i * t2)
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

STATIC INLINE void aes_256_assist2(__m128i* t1, __m128i * t3)
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

STATIC INLINE void aes_pseudo_round(const uint8_t *in, uint8_t *out,
                                    const uint8_t *expandedKey, int nblocks)
{
    __m128i *k = R128(expandedKey);
    __m128i d;
    int i;

    for(i = 0; i < nblocks; i++)
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

STATIC INLINE void aes_pseudo_round_xor(const uint8_t *in, uint8_t *out,
                                        const uint8_t *expandedKey, const uint8_t *xor, int nblocks)
{
    __m128i *k = R128(expandedKey);
    __m128i *x = R128(xor);
    __m128i d;
    int i;

    for(i = 0; i < nblocks; i++)
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
    if(!OpenProcessToken(hProcess, TOKEN_ADJUST_PRIVILEGES, &token))
        return FALSE;

    info.count = 1;
    info.privilege[0].Attributes = bEnable ? SE_PRIVILEGE_ENABLED : 0;

    if(!LookupPrivilegeValue(NULL, SE_LOCK_MEMORY_NAME, &(info.privilege[0].Luid)))
        return FALSE;

    if(!AdjustTokenPrivileges(token, FALSE, (PTOKEN_PRIVILEGES) &info, 0, NULL, NULL))
        return FALSE;

    if (GetLastError() != ERROR_SUCCESS)
        return FALSE;

    CloseHandle(token);

    return TRUE;

}
#endif

static uint32_t allocated_memory = 0;

void slow_hash_allocate_state(uint32_t memory)
{
    allocated_memory = memory;

    if(hp_state != NULL)
        return;

#if defined(_MSC_VER) || defined(__MINGW32__)
    SetLockPagesPrivilege(GetCurrentProcess(), TRUE);
    hp_state = (uint8_t *) VirtualAlloc(hp_state, memory, MEM_LARGE_PAGES |
                                        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
#else
#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || \
  defined(__DragonFly__) || defined(__NetBSD__)
    hp_state = mmap(0, memory, PROT_READ | PROT_WRITE,
                    MAP_PRIVATE | MAP_ANON, 0, 0);
#else
    hp_state = mmap(0, memory, PROT_READ | PROT_WRITE,
                    MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB, 0, 0);
#endif
    if(hp_state == MAP_FAILED)
        hp_state = NULL;
#endif
    hp_allocated = 1;
    if(hp_state == NULL)
    {
        hp_allocated = 0;
        hp_state = (uint8_t *) malloc(memory);
    }
}

/**
 *@brief frees the state allocated by slow_hash_allocate_state
 */

void slow_hash_free_state(uint32_t memory)
{
    if(hp_state == NULL)
        return;

    if(!hp_allocated)
        free(hp_state);
    else
    {
#if defined(_MSC_VER) || defined(__MINGW32__)
        VirtualFree(hp_state, 0, MEM_RELEASE);
#else
        munmap(hp_state, memory);
#endif
    }

    hp_state = NULL;
    hp_allocated = 0;
}

void cn_slow_hash(const void *data, size_t length, char *hash, int variant, int prehashed, size_t base_iters, size_t rand_iters, random_values *r, const char* sp_bytes, 
    uint8_t init_size_blk, uint16_t xx, uint16_t yy, uint16_t zz, uint16_t ww, uint32_t memory)
{
    uint32_t init_size_byte = (init_size_blk * AES_BLOCK_SIZE);
    RDATA_ALIGN16 uint8_t expandedKey[240];  /* These buffers are aligned to use later with SSE functions */

    uint8_t* text = (uint8_t*)malloc(init_size_byte);
    RDATA_ALIGN16 uint64_t a[2];
    RDATA_ALIGN16 uint64_t b[4];
    RDATA_ALIGN16 uint64_t c[2];
    union cn_slow_hash_state state;
    __m128i _a, _b, _b1, _c;
    uint64_t hi, lo;

    size_t i, j;
    uint64_t *p = NULL;
    oaes_ctx *aes_ctx = NULL;
    int useAes = !force_software_aes() && check_aes_hw();

    static void (*const extra_hashes[4])(const void *, size_t, char *) =
    {
        hash_extra_blake, hash_extra_groestl, hash_extra_jh, hash_extra_skein
    };

    // quick hack to make sure the pad is the right size when transitioning to the new fork
    if (memory != allocated_memory && hp_state != NULL)
        slow_hash_free_state(allocated_memory);

    if(hp_state == NULL)
        slow_hash_allocate_state(memory);
        
    /* CryptoNight Step 1:  Use Keccak1600 to initialize the 'state' (and 'text') buffers from the data. */
    if (prehashed) {
        memcpy(&state.hs, data, length);
    } else {
        hash_process(&state.hs, data, length);
    }
    memcpy(text, state.init, init_size_byte);

    VARIANT1_INIT64();
    VARIANT2_INIT64();

    /* CryptoNight Step 2:  Iteratively encrypt the results from Keccak to fill
     * the 2MB large random access buffer.
     */

    if(useAes)
    {
        aes_expand_key(state.hs.b, expandedKey);
        for(i = 0; i < memory / init_size_byte; i++)
        {
            aes_pseudo_round(text, text, expandedKey, init_size_blk);
            memcpy(&hp_state[i * init_size_byte], text, init_size_byte);
        }
    }
    else
    {
        aes_ctx = (oaes_ctx *) oaes_alloc();
        oaes_key_import_data(aes_ctx, state.hs.b, AES_KEY_SIZE);
        for(i = 0; i < memory / init_size_byte; i++)
        {
            for(j = 0; j < init_size_blk; j++)
                aesb_pseudo_round(&text[AES_BLOCK_SIZE * j], &text[AES_BLOCK_SIZE * j], aes_ctx->key->exp_data);

            memcpy(&hp_state[i * init_size_byte], text, init_size_byte);
        }
    }

    randomize_scratchpad(r, sp_bytes, hp_state, variant);

    U64(a)[0] = U64(&state.k[0])[0] ^ U64(&state.k[32])[0];
    U64(a)[1] = U64(&state.k[0])[1] ^ U64(&state.k[32])[1];
    U64(b)[0] = U64(&state.k[16])[0] ^ U64(&state.k[48])[0];
    U64(b)[1] = U64(&state.k[16])[1] ^ U64(&state.k[48])[1];

    /* CryptoNight Step 3:  Bounce randomly 1,048,576 times (1<<20) through the mixing buffer,
     * using 524,288 iterations of the following mixing function.  Each execution
     * performs two reads and writes from the mixing buffer.
     */

    _b = _mm_load_si128(R128(b));
    _b1 = _mm_load_si128(R128(b) + 1);

    uint16_t k = 1, l = 1, m = 1;
    uint16_t r2[6] = { xx ^ yy, xx ^ zz, xx ^ ww, yy ^ zz, yy ^ ww, zz ^ ww };

    if(useAes)
    {
        if (variant <= 3)
        {
            for(i = 0; i < base_iters; i++)
            {
                pre_aes();
                _c = _mm_aesenc_si128(_c, _a);
                post_aes(0, 0);
            }
        }
        else
        {
            for(k = 1; k < xx; k++)
            {
                r2[0] ^= r2[1];
                r2[1] ^= r2[2];
                r2[2] ^= r2[3];
                r2[3] ^= r2[4];
                r2[4] ^= r2[5];
                r2[5] ^= r2[0];

                pre_aes();
                _c = _mm_aesenc_si128(_c, _a);
                post_aes(r2[0] % 2, r2[1] % 2);
                r2[0] ^= (r2[1] ^ r2[3]);
                r2[1] ^= (r2[0] ^ r2[2]);

                for(l = 1; l < yy; l++)
                {
                    pre_aes();
                    _c = _mm_aesenc_si128(_c, _a);
                    post_aes(r2[2] % 2, r2[3] % 2);
                    r2[2] ^= (r2[3] ^ r2[5]);
                    r2[3] ^= (r2[2] ^ r2[4]);

                    for(m = 1; m < zz; m++)
                    {
                        pre_aes();
                        _c = _mm_aesenc_si128(_c, _a);
                        post_aes(r2[4] % 2, r2[5] % 2);
                        r2[4] ^= (r2[5] ^ r2[1]);
                        r2[5] ^= (r2[4] ^ r2[0]);
                    }
                }
            }
        }
        
        for(i = 0; i < rand_iters; i++)
        {
            pre_aes();
            _c = _mm_aesenc_si128(_c, _a);
            post_aes(0, 0);
        }
    }
    else
    {
        if (variant <= 3)
        {
            for(i = 0; i < base_iters; i++)
            {
                pre_aes();
                aesb_single_round((uint8_t *) &_c, (uint8_t *) &_c, (uint8_t *) &_a);
                post_aes(0, 0);
            }
        }
        else
        {
            for(k = 1; k < xx; k++)
            {
                r2[0] ^= r2[1];
                r2[1] ^= r2[2];
                r2[2] ^= r2[3];
                r2[3] ^= r2[4];
                r2[4] ^= r2[5];
                r2[5] ^= r2[0];

                pre_aes();
                aesb_single_round((uint8_t *) &_c, (uint8_t *) &_c, (uint8_t *) &_a);
                post_aes(r2[0] % 2, r2[1] % 2);
                r2[0] ^= (r2[1] ^ r2[3]);
                r2[1] ^= (r2[0] ^ r2[2]);

                for(l = 1; l < yy; l++)
                {
                    pre_aes();
                    aesb_single_round((uint8_t *) &_c, (uint8_t *) &_c, (uint8_t *) &_a);
                    post_aes(r2[2] % 2, r2[3] % 2);
                    r2[2] ^= (r2[3] ^ r2[5]);
                    r2[3] ^= (r2[2] ^ r2[4]);

                    for(m = 1; m < zz; m++)
                    {
                        pre_aes();
                        aesb_single_round((uint8_t *) &_c, (uint8_t *) &_c, (uint8_t *) &_a);
                        post_aes(r2[4] % 2, r2[5] % 2);
                        r2[4] ^= (r2[5] ^ r2[1]);
                        r2[5] ^= (r2[4] ^ r2[0]);
                    }
                }
            }
        }

        for(i = 0; i < rand_iters; i++)
        {
            pre_aes();
            aesb_single_round((uint8_t *) &_c, (uint8_t *) &_c, (uint8_t *) &_a);
            post_aes(0, 0);
        }
    }

    /* CryptoNight Step 4:  Sequentially pass through the mixing buffer and use 10 rounds
     * of AES encryption to mix the random data back into the 'text' buffer.  'text'
     * was originally created with the output of Keccak1600. */

    memcpy(text, state.init, init_size_byte);
    if(useAes)
    {
        aes_expand_key(&state.hs.b[32], expandedKey);
        for(i = 0; i < memory / init_size_byte; i++)
            aes_pseudo_round_xor(text, text, expandedKey, &hp_state[i * init_size_byte], init_size_blk);
    }
    else
    {
        oaes_key_import_data(aes_ctx, &state.hs.b[32], AES_KEY_SIZE);
        for(i = 0; i < memory / init_size_byte; i++)
        {
            for(j = 0; j < init_size_blk; j++)
            {
                xor_blocks(&text[j * AES_BLOCK_SIZE], &hp_state[i * init_size_byte + j * AES_BLOCK_SIZE]);
                aesb_pseudo_round(&text[AES_BLOCK_SIZE * j], &text[AES_BLOCK_SIZE * j], aes_ctx->key->exp_data);
            }
        }
        oaes_free((OAES_CTX **) &aes_ctx);
    }

    /* CryptoNight Step 5:  Apply Keccak to the state again, and then
     * use the resulting data to select which of four finalizer
     * hash functions to apply to the data (Blake, Groestl, JH, or Skein).
     * Use this hash to squeeze the state array down
     * to the final 256 bit hash output.
     */

    memcpy(state.init, text, init_size_byte);
    hash_permutation(&state.hs);
    extra_hashes[state.hs.b[0] & 3](&state, 200, hash);

    free(text);
}

#else
// Portable implementation as a fallback

void slow_hash_allocate_state(uint32_t memory)
{
  // Do nothing, this is just to maintain compatibility with the upgraded slow-hash.c
  return;
}

void slow_hash_free_state(void)
{
  // As above
  return;
}

static void (*const extra_hashes[4])(const void *, size_t, char *) = {
  hash_extra_blake, hash_extra_groestl, hash_extra_jh, hash_extra_skein
};

static size_t e2i(const uint8_t* a, size_t count) { return (*((uint64_t*)a) / AES_BLOCK_SIZE) & (count - 1); }

static void mul(const uint8_t* a, const uint8_t* b, uint8_t* res) {
  uint64_t a0, b0;
  uint64_t hi, lo;

  a0 = SWAP64LE(((uint64_t*)a)[0]);
  b0 = SWAP64LE(((uint64_t*)b)[0]);
  lo = mul128(a0, b0, &hi);
  ((uint64_t*)res)[0] = SWAP64LE(hi);
  ((uint64_t*)res)[1] = SWAP64LE(lo);
}

static void sum_half_blocks(uint8_t* a, const uint8_t* b) {
  uint64_t a0, a1, b0, b1;

  a0 = SWAP64LE(((uint64_t*)a)[0]);
  a1 = SWAP64LE(((uint64_t*)a)[1]);
  b0 = SWAP64LE(((uint64_t*)b)[0]);
  b1 = SWAP64LE(((uint64_t*)b)[1]);
  a0 += b0;
  a1 += b1;
  ((uint64_t*)a)[0] = SWAP64LE(a0);
  ((uint64_t*)a)[1] = SWAP64LE(a1);
}
#define U64(x) ((uint64_t *) (x))

static void copy_block(uint8_t* dst, const uint8_t* src) {
  memcpy(dst, src, AES_BLOCK_SIZE);
}

static void swap_blocks(uint8_t *a, uint8_t *b){
  uint64_t t[2];
  U64(t)[0] = U64(a)[0];
  U64(t)[1] = U64(a)[1];
  U64(a)[0] = U64(b)[0];
  U64(a)[1] = U64(b)[1];
  U64(b)[0] = U64(t)[0];
  U64(b)[1] = U64(t)[1];
}

static void xor_blocks(uint8_t* a, const uint8_t* b) {
  size_t i;
  for (i = 0; i < AES_BLOCK_SIZE; i++) {
    a[i] ^= b[i];
  }
}

static void xor64(uint8_t* left, const uint8_t* right)
{
  size_t i;
  for (i = 0; i < 8; ++i)
  {
    left[i] ^= right[i];
  }
}

#pragma pack(push, 1)
union cn_slow_hash_state {
  union hash_state hs;
  struct {
    uint8_t k[64];
    uint8_t init[128];
  };
};
#pragma pack(pop)

void cn_slow_hash(const void *data, size_t length, char *hash, int variant, int prehashed, size_t base_iters, size_t rand_iters, random_values *r, const char* sp_bytes, 
    uint8_t init_size_blk, uint16_t xx, uint16_t yy, uint16_t zz, uint16_t ww, uint32_t memory) {

  uint8_t *long_state = (uint8_t *)malloc(memory);

  union cn_slow_hash_state state;
  uint32_t init_size_byte = (init_size_blk * AES_BLOCK_SIZE);
  uint8_t* text = (uint8_t*)malloc(init_size_byte);
  uint8_t a[AES_BLOCK_SIZE];
  uint8_t b[AES_BLOCK_SIZE * 2];
  uint8_t c1[AES_BLOCK_SIZE];
  uint8_t c2[AES_BLOCK_SIZE];
  uint8_t d[AES_BLOCK_SIZE];
  size_t i, j;
  uint8_t aes_key[AES_KEY_SIZE];
  oaes_ctx *aes_ctx;

  if (prehashed) {
    memcpy(&state.hs, data, length);
  } else {
    hash_process(&state.hs, data, length);
  }
  memcpy(text, state.init, init_size_byte);
  memcpy(aes_key, state.hs.b, AES_KEY_SIZE);
  aes_ctx = (oaes_ctx *) oaes_alloc();

  VARIANT1_PORTABLE_INIT();
  VARIANT2_PORTABLE_INIT();

  oaes_key_import_data(aes_ctx, aes_key, AES_KEY_SIZE);
  for (i = 0; i < memory / init_size_byte; i++) {
    for (j = 0; j < init_size_blk; j++) {
      aesb_pseudo_round(&text[AES_BLOCK_SIZE * j], &text[AES_BLOCK_SIZE * j], aes_ctx->key->exp_data);
    }
    memcpy(&long_state[i * init_size_byte], text, init_size_byte);
  }

  randomize_scratchpad(r, sp_bytes, long_state, variant);

  for (i = 0; i < AES_BLOCK_SIZE; i++) {
    a[i] = state.k[     i] ^ state.k[AES_BLOCK_SIZE * 2 + i];
    b[i] = state.k[AES_BLOCK_SIZE + i] ^ state.k[AES_BLOCK_SIZE * 3 + i];
  }

  uint16_t k = 1, l = 1, m = 1;
  uint16_t r2[6] = { xx ^ yy, xx ^ zz, xx ^ ww, yy ^ zz, yy ^ ww, zz ^ ww };

  if (variant <= 3)
  {
    for (i = 0; i < base_iters; i++)
    {
        j = e2i(a, memory / AES_BLOCK_SIZE) * AES_BLOCK_SIZE;
        copy_block(c1, &long_state[j]);
        aesb_single_round(c1, c1, a);
        copy_block(&long_state[j], c1);
        xor_blocks(&long_state[j], b);
        assert(j == e2i(a, memory / AES_BLOCK_SIZE) * AES_BLOCK_SIZE);
        VARIANT1_1(&long_state[j]);

        j = e2i(c1, memory / AES_BLOCK_SIZE) * AES_BLOCK_SIZE;
        copy_block(c2, &long_state[j]);
        mul(c1, c2, d);
        swap_blocks(a, c1);
        sum_half_blocks(c1, d);
        swap_blocks(c1, c2);
        xor_blocks(c1, c2);
        VARIANT1_2(c2 + 8);
        copy_block(&long_state[j], c2);
        assert(j == e2i(a, memory / AES_BLOCK_SIZE) * AES_BLOCK_SIZE);
        copy_block(b + AES_BLOCK_SIZE, b);
        copy_block(b, a);
        copy_block(a, c1);
    }
  }
  else
  {
    for(k = 1; k < xx; k++)
    {
        r2[0] ^= r2[1];
        r2[1] ^= r2[2];
        r2[2] ^= r2[3];
        r2[3] ^= r2[4];
        r2[4] ^= r2[5];
        r2[5] ^= r2[0];

        j = e2i(a, memory / AES_BLOCK_SIZE) * AES_BLOCK_SIZE;
        copy_block(c1, &long_state[j]);
        aesb_single_round(c1, c1, a);
        copy_block(&long_state[j], c1);
        xor_blocks(&long_state[j], b);
        assert(j == e2i(a, memory / AES_BLOCK_SIZE) * AES_BLOCK_SIZE);
        VARIANT1_1(&long_state[j]);

        j = e2i(c1, memory / AES_BLOCK_SIZE) * AES_BLOCK_SIZE;
        copy_block(c2, &long_state[j]);
        mul(c1, c2, d);
        if (r2[1] % 2)
            VARIANT2_2_PORTABLE();
        if (r2[0] % 2)
            VARIANT2_PORTABLE_SHUFFLE_ADD(long_state, j);
        swap_blocks(a, c1);
        sum_half_blocks(c1, d);
        swap_blocks(c1, c2);
        xor_blocks(c1, c2);
        VARIANT1_2(c2 + 8);
        copy_block(&long_state[j], c2);
        assert(j == e2i(a, memory / AES_BLOCK_SIZE) * AES_BLOCK_SIZE);
        copy_block(b + AES_BLOCK_SIZE, b);
        copy_block(b, a);
        copy_block(a, c1);

        r2[0] ^= (r2[1] ^ r2[3]);
        r2[1] ^= (r2[0] ^ r2[2]);

        for(l = 1; l < yy; l++)
        {
            j = e2i(a, memory / AES_BLOCK_SIZE) * AES_BLOCK_SIZE;
            copy_block(c1, &long_state[j]);
            aesb_single_round(c1, c1, a);
            copy_block(&long_state[j], c1);
            xor_blocks(&long_state[j], b);
            assert(j == e2i(a, memory / AES_BLOCK_SIZE) * AES_BLOCK_SIZE);
            VARIANT1_1(&long_state[j]);

            j = e2i(c1, memory / AES_BLOCK_SIZE) * AES_BLOCK_SIZE;
            copy_block(c2, &long_state[j]);
            mul(c1, c2, d);
            if (r2[3] % 2)
                VARIANT2_2_PORTABLE();
            if (r2[2] % 2)
                VARIANT2_PORTABLE_SHUFFLE_ADD(long_state, j);
            swap_blocks(a, c1);
            sum_half_blocks(c1, d);
            swap_blocks(c1, c2);
            xor_blocks(c1, c2);
            VARIANT1_2(c2 + 8);
            copy_block(&long_state[j], c2);
            assert(j == e2i(a, memory / AES_BLOCK_SIZE) * AES_BLOCK_SIZE);
            copy_block(b + AES_BLOCK_SIZE, b);
            copy_block(b, a);
            copy_block(a, c1);

            r2[2] ^= (r2[3] ^ r2[5]);
            r2[3] ^= (r2[2] ^ r2[4]);

            for(m = 1; m < zz; m++)
            {
                j = e2i(a, memory / AES_BLOCK_SIZE) * AES_BLOCK_SIZE;
                copy_block(c1, &long_state[j]);
                aesb_single_round(c1, c1, a);
                copy_block(&long_state[j], c1);
                xor_blocks(&long_state[j], b);
                assert(j == e2i(a, memory / AES_BLOCK_SIZE) * AES_BLOCK_SIZE);
                VARIANT1_1(&long_state[j]);

                j = e2i(c1, memory / AES_BLOCK_SIZE) * AES_BLOCK_SIZE;
                copy_block(c2, &long_state[j]);
                mul(c1, c2, d);
                if (r2[5] % 2)
                    VARIANT2_2_PORTABLE();
                if (r2[4] % 2)
                    VARIANT2_PORTABLE_SHUFFLE_ADD(long_state, j);
                swap_blocks(a, c1);
                sum_half_blocks(c1, d);
                swap_blocks(c1, c2);
                xor_blocks(c1, c2);
                VARIANT1_2(c2 + 8);
                copy_block(&long_state[j], c2);
                assert(j == e2i(a, memory / AES_BLOCK_SIZE) * AES_BLOCK_SIZE);
                copy_block(b + AES_BLOCK_SIZE, b);
                copy_block(b, a);
                copy_block(a, c1);

                r2[4] ^= (r2[5] ^ r2[1]);
                r2[5] ^= (r2[4] ^ r2[0]);
            }
        }
    }
  }

  for (i = 0; i < rand_iters; i++)
  {
    j = e2i(a, memory / AES_BLOCK_SIZE) * AES_BLOCK_SIZE;
    copy_block(c1, &long_state[j]);
    aesb_single_round(c1, c1, a);
    copy_block(&long_state[j], c1);
    xor_blocks(&long_state[j], b);
    assert(j == e2i(a, memory / AES_BLOCK_SIZE) * AES_BLOCK_SIZE);
    VARIANT1_1(&long_state[j]);

    j = e2i(c1, memory / AES_BLOCK_SIZE) * AES_BLOCK_SIZE;
    copy_block(c2, &long_state[j]);
    mul(c1, c2, d);
    swap_blocks(a, c1);
    sum_half_blocks(c1, d);
    swap_blocks(c1, c2);
    xor_blocks(c1, c2);
    VARIANT1_2(c2 + 8);
    copy_block(&long_state[j], c2);
    assert(j == e2i(a, memory / AES_BLOCK_SIZE) * AES_BLOCK_SIZE);
    copy_block(b + AES_BLOCK_SIZE, b);
    copy_block(b, a);
    copy_block(a, c1);
  }

  memcpy(text, state.init, init_size_byte);
  oaes_key_import_data(aes_ctx, &state.hs.b[32], AES_KEY_SIZE);
  for (i = 0; i < memory / init_size_byte; i++) {
    for (j = 0; j < init_size_blk; j++) {
      xor_blocks(&text[j * AES_BLOCK_SIZE], &long_state[i * init_size_byte + j * AES_BLOCK_SIZE]);
      aesb_pseudo_round(&text[AES_BLOCK_SIZE * j], &text[AES_BLOCK_SIZE * j], aes_ctx->key->exp_data);
    }
  }
  memcpy(state.init, text, init_size_byte);
  hash_permutation(&state.hs);
  /*memcpy(hash, &state, 32);*/
  extra_hashes[state.hs.b[0] & 3](&state, 200, hash);
  oaes_free((OAES_CTX **) &aes_ctx);
  free(text);
  free(long_state);
}

#endif

void randomize_scratchpad(random_values *r, const char* salt, uint8_t* scratchpad, uint32_t variant)
{
    if (variant <= 1)
        return;

    if (variant >= 4)
    {
        uint32_t memory = 1024 * 256;
        for (uint32_t i = 0; i < memory; i ++)
            scratchpad[i] = scratchpad[i] ^ salt[i];
    }
    else if (variant >= 3)
    {
        uint32_t memory = 1024 * 1024;
        uint32_t step = memory / (32 * 128);
        uint32_t x = 0;
        for (uint32_t i = 0; i < memory; i += step)
            scratchpad[i] = scratchpad[i] ^ salt[x++];
    }

    for (int i = 0; i < RANDOM_VALUES; i++)
    {
        switch (r->operators[i])
        {
            case ADD:
                scratchpad[r->indices[i]] += r->values[i];
                break;
            case SUB:
                scratchpad[r->indices[i]] -= r->values[i];
                break;
            case XOR:
                scratchpad[r->indices[i]] ^= r->values[i];
                break;
            case OR:
                scratchpad[r->indices[i]] |= r->values[i];
                break;
            case AND:
                scratchpad[r->indices[i]] &= r->values[i];
                break;
            case COMP:
                scratchpad[r->indices[i]] = ~r->values[i];
                break;
            case EQ:
                scratchpad[r->indices[i]] = r->values[i];
                break;
        }
    }
}
