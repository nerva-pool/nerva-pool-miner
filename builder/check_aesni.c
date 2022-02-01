#include <stdio.h>
#include <stdbool.h>
#include <cpuid.h>

static void _cpuid(unsigned int leaf, unsigned int *cpuinfo)
{
    __cpuid_count(leaf, 0, cpuinfo[0], cpuinfo[1], cpuinfo[2], cpuinfo[3]);
}

bool has_aesni()
{
    unsigned int cpuinfo[4];
    _cpuid(0, cpuinfo);
    if (cpuinfo[0] == 0)
        return false;
    
    _cpuid(1, cpuinfo);
    return cpuinfo[2] & (1 << 25);
}

bool main(void)
{
    if (!has_aesni())
    {
        printf("AES-NI: Not supported.\n");
        return false;
    }
    else
    {
        printf("AES-NI: Supported.\n");
        return true;
    }
}
