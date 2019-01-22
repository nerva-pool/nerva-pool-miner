// Copyright (c) 2018, The NERVA Project
//Implementation of a Mersenne Twister random number generator
#ifndef _MERSENNE_TWISTER_
#define _MERSENNE_TWISTER_

#include <stdint.h>
#include <limits>

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

            inline uint32_t TEMPERING_SHIFT_U(uint32_t y)
            {
                return (y >> 11);
            } 

            inline uint32_t TEMPERING_SHIFT_S(uint32_t y)
            {
                return (y << 7);
            }

            inline uint32_t TEMPERING_SHIFT_T(uint32_t y)
            {
                return (y << 15);
            }

            inline uint32_t TEMPERING_SHIFT_L(uint32_t y)
            {
                return (y >> 18);
            }
            
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
                y ^= TEMPERING_SHIFT_U(y);
                y ^= TEMPERING_SHIFT_S(y) & TEMPERING_MASK_B;
                y ^= TEMPERING_SHIFT_T(y) & TEMPERING_MASK_C;
                y ^= TEMPERING_SHIFT_L(y);

                return y;
            }

            uint32_t next(uint32_t min, uint32_t max)
            {
                uint32_t r = generate_uint();
                double div = (double)(0xffffffff) / (double)(max - min);
                return (r / div) + min;
            }

            void next_bytes(uint8_t* data, uint32_t length)
            {
                for (uint32_t i = 0; i < length; i++)
                    data[i] = (uint8_t)(generate_uint() / (0xffffffff / (uint32_t)0xff));
            }

            void next_bytes(char* data, uint32_t length)
            {
                for (uint32_t i = 0; i < length; i++)
                    data[i] = (char)(generate_uint() / (0xffffffff / (uint32_t)0xff));
            }

            //generate number sequence for v3/4
            std::array<uint32_t, 36864> generate_v3_sequence(uint32_t seed, uint32_t height)
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
};

#endif
