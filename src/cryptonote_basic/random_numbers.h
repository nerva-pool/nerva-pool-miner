// Copyright (c) 2018, The NERVA Project
#ifndef _RANDOM_NUMBERS_
#define _RANDOM_NUMBERS_

#include <stdint.h>
#include <limits>
#include <xmmintrin.h>
#include <smmintrin.h>

#ifndef RDATA_ALIGN16
    #if defined(_MSC_VER)
        #define RDATA_ALIGN16 __declspec(align(16))
    #else
        #define RDATA_ALIGN16 __attribute__ ((aligned(16)))
    #endif
#endif

namespace angrywasp
{
    class mersenne_twister
    {
        private:

            static const uint32_t N = 624;
            static const uint32_t M = 397;
            static const uint32_t MATRIX_A = 0x9908b0df;
            static const uint32_t UPPER_MASK = 0x80000000;
            static const uint32_t LOWER_MASK = 0x7fffffff; 
            static const uint32_t TEMPERING_MASK_B = 0x9d2c5680;
            static const uint32_t TEMPERING_MASK_C = 0xefc60000;

            const uint32_t mag01[2] = { 0x0, MATRIX_A };
            
            uint32_t mt[N] = { 0 };
            uint16_t mti = 0;

        public:

            mersenne_twister(uint32_t seed)
            {
                set_seed(seed);
            }

            void set_seed(uint32_t seed)
            {
                mt[0] = seed & 0xffffffff;
                for (mti = 1; mti < N; mti++)
                    mt[mti] = (69069 * mt[mti - 1]) & 0xffffffff;
            }

            uint32_t generate_uint()
            {
                uint32_t y;

                if (mti >= N)
                {
                    uint32_t kk;

                    for (kk = 0; kk < N - M; kk++)
                    {
                        y = (mt[kk] & UPPER_MASK) | (mt[kk + 1] & LOWER_MASK);
                        mt[kk] = mt[kk + M] ^ (y >> 1) ^ mag01[y & 0x1];
                    }

                    for (; kk < N - 1; kk++)
                    {
                        y = (mt[kk] & UPPER_MASK) | (mt[kk + 1] & LOWER_MASK);
                        mt[kk] = mt[kk + (M - N)] ^ (y >> 1) ^ mag01[y & 0x1];
                    }

                    y = (mt[N - 1] & UPPER_MASK) | (mt[0] & LOWER_MASK);
                    mt[N - 1] = mt[M - 1] ^ (y >> 1) ^ mag01[y & 0x1];

                    mti = 0;
                }

                y = mt[mti++];
                y ^= (y >> 11);
                y ^= (y << 7) & TEMPERING_MASK_B;
                y ^= (y << 15) & TEMPERING_MASK_C;
                y ^= (y >> 18);

                return y;
            }

            uint32_t next(uint32_t min, uint32_t max)
            {
                uint32_t r = generate_uint();
                double div = (double)(0xffffffff) / (double)(max - min);
                return (r / div) + min;
            }

            std::array<uint32_t, 36864> generate_v4_sequence(uint32_t seed, uint32_t height)
            {
              std::array<uint32_t, 36864> reval;
              size_t oIndex = 0;
              uint32_t y, r;
              for(size_t i = 0; i < 2048; ++i)
              {
                {
                  uint32_t kk;
                  for (kk = 0; kk < 27; kk++)
                  {
                      y = (mt[kk] & UPPER_MASK) | (mt[kk + 1] & LOWER_MASK);
                      mt[kk] = mt[kk + M] ^ (y >> 1) ^ mag01[y & 0x1];
                  }
                  mti = 0;
                }

                reval[oIndex++] = next(1, (uint32_t)(height - 1));

                for(uint8_t j = 0; j < 4; ++j)
                {
                  r = next(6, (uint32_t)(height - 6));
                  reval[oIndex++] = next(r - 5, r + 5);
                  reval[oIndex++] = next(r - 5, r + 5);
                  
                  r = next(6, (uint32_t)(height - 6));
                  reval[oIndex++] = next(r - 5, r + 5);
                  reval[oIndex++] = next(r - 5, r + 5);
                }

                reval[oIndex++] = next(1, (uint32_t)(height - 1));
                set_seed(seed ^ generate_uint());
              }
              return reval;
            }
    };

    class mwc1616
    {
        private:

            const RDATA_ALIGN16 uint32_t  msk[4];
            const RDATA_ALIGN16 uint32_t mul1[4];
            const RDATA_ALIGN16 uint32_t mul2[4];

            union Split64
            {
                uint64_t u;
                struct {
                    uint32_t a;
                    uint32_t b;
                };
            };

        public:

        mwc1616() : msk{ 0xFFFF }, mul1{ 0x4650 }, mul2{ 0x78B7 } { }

        uint32_t next(char* input, uint32_t seed, uint32_t* rng_result)
        {
            for (int i = 0; i < 32; i += 8)
            {
                seed = (seed * 0x6DE6ECDE5DULL + 0xBULL) & ((1ULL << 48) - 1);
                *(uint32_t*)&input[i] ^= seed;
            }

            uint16_t* st = (uint16_t*)input;

            RDATA_ALIGN16 uint32_t sa[4] =
            {
                ((uint32_t)st[ 0] << 16) | st[ 2],
                ((uint32_t)st[ 1] << 16) | st[ 3],
                ((uint32_t)st[ 4] << 16) | st[ 6],
                ((uint32_t)st[ 5] << 16) | st[ 7]
            };
            RDATA_ALIGN16 uint32_t sb[4] =
            {
                ((uint32_t)st[ 8] << 16) | st[10],
                ((uint32_t)st[ 9] << 16) | st[11],
                ((uint32_t)st[12] << 16) | st[14],
                ((uint32_t)st[13] << 16) | st[14]
            };

            uint64_t result[2] = { 0 };

            #if !defined(NO_SSE4)
                __m128i a = _mm_load_si128((const __m128i *)sa);
                __m128i b = _mm_load_si128((const __m128i *)sb);

                const __m128i mask = _mm_load_si128((const __m128i *)msk);
                const __m128i m1 = _mm_load_si128((const __m128i *)mul1);
                const __m128i m2 = _mm_load_si128((const __m128i *)mul2);

                __m128i amask = _mm_and_si128(a, mask);
                __m128i ashift = _mm_srli_epi32(a, 0x10);
                __m128i amul = _mm_mullo_epi32(amask, m1);
                __m128i anew = _mm_add_epi32(amul, ashift);
                _mm_store_si128((__m128i *)sa, anew);

                __m128i bmask = _mm_and_si128(b, mask);
                __m128i bshift = _mm_srli_epi32(b, 0x10);
                __m128i bmul = _mm_mullo_epi32(bmask, m2);
                __m128i bnew = _mm_add_epi32(bmul, bshift);
                _mm_store_si128((__m128i *)sb, bnew);

                __m128i bmasknew = _mm_and_si128(bnew, mask);
                __m128i ashiftnew = _mm_slli_epi32(anew, 0x10);
                __m128i res = _mm_add_epi32(ashiftnew, bmasknew);
                _mm_store_si128((__m128i *)result, res);
            #else
                __m128i a = _mm_load_si128((const __m128i *)sa);
                __m128i b = _mm_load_si128((const __m128i *)sb);

                const __m128i mask = _mm_load_si128((const __m128i *)msk);
                const __m128i m1 = _mm_load_si128((const __m128i *)mul1);
                const __m128i m2 = _mm_load_si128((const __m128i *)mul2);

                __m128i ashift = _mm_srli_epi32(a, 0x10);
                __m128i amask = _mm_and_si128(a, mask);
                __m128i amullow = _mm_mullo_epi16(amask, m1);
                __m128i amulhigh = _mm_mulhi_epu16(amask, m1);
                __m128i amulhigh_shift = _mm_slli_epi32(amulhigh, 0x10);
                __m128i amul = _mm_or_si128(amullow, amulhigh_shift);
                __m128i anew = _mm_add_epi32(amul, ashift);
                _mm_store_si128((__m128i *)sa, anew);

                __m128i bshift = _mm_srli_epi32(b, 0x10);
                __m128i bmask = _mm_and_si128(b, mask);
                __m128i bmullow = _mm_mullo_epi16(bmask, m2);
                __m128i bmulhigh = _mm_mulhi_epu16(bmask, m2);
                __m128i bmulhigh_shift = _mm_slli_epi32(bmulhigh, 0x10);
                __m128i bmul = _mm_or_si128(bmullow, bmulhigh_shift);
                __m128i bnew = _mm_add_epi32(bmul, bshift);
                _mm_store_si128((__m128i *)sb, bnew);

                __m128i bmasknew = _mm_and_si128(bnew, mask);
                __m128i ashiftnew = _mm_slli_epi32(anew, 0x10);
                __m128i res = _mm_add_epi32(ashiftnew, bmasknew);
                _mm_store_si128((__m128i *)result, res);
            #endif

            union Split64 y;
            y.u = result[0] ^ result[1];

            *rng_result = (y.a ^ y.b);
            return seed;
        }

        uint32_t next(char* input, uint32_t seed, uint32_t min, uint32_t max, uint32_t* rng_result)
        {
            uint32_t r;
            seed = next(input, seed, &r);

            double div = (double)(0xffffffff) / (double)(max - min);
            *rng_result = ((double)(r) / div) + (double)min;
            return seed;
        }
    };
};

#endif
