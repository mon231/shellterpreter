// Self-registration of the shellcode's own image layout with the interpreter.
//
// The interpreter never parses the shellcode blob. Image-relative services
// (x64 table-based exception handling, FindResourceA/SizeofResource) read a
// descriptor block that the shellcode itself writes into the emulated
// environment, using the TEB self-pointer the environment provides at
// gs:[30h] (x64) / fs:[18h] (x86). The shellcode owns its bytes, so it may
// read its own PE headers here; the interpreter still never does.
//
// Offsets must mirror kDescRva/kTebRva/kDescMagic in
// shellterpreter/guest_environment.hpp.
//
// SELFREG_SKEW (optional, defined at build time): shift the registered image
// base by this many bytes - used by the fail-closed tests.
#ifndef SELFREG_H
#define SELFREG_H

#include <stdint.h>
#include <intrin.h>

#ifdef __cplusplus
extern "C" const unsigned char __ImageBase; // linker-provided, image RVA 0
#else
extern const unsigned char __ImageBase;
#endif

#define SELFREG_DESC_RVA 0x1400u
#define SELFREG_TEB_RVA  0x100u
#define SELFREG_MAGIC    0x52445348u /* 'RDSH' */

static void selfRegisterLayout(void)
{
    const uint8_t* dos = (const uint8_t*)&__ImageBase;
    const uint32_t lfanew = *(const uint32_t*)(dos + 0x3C);
    const uint8_t* pe = dos + lfanew;
    const uint16_t optMagic = *(const uint16_t*)(pe + 24);
    const uint8_t* dd = pe + 24 + (optMagic == 0x20B ? 0x70u : 0x60u);
    const uint32_t resRva = *(const uint32_t*)(dd + 2 * 8);
    const uint32_t pdataRva = *(const uint32_t*)(dd + 3 * 8);
    const uint32_t pdataSize = *(const uint32_t*)(dd + 3 * 8 + 4);

    uintptr_t base = (uintptr_t)&__ImageBase;
#ifdef SELFREG_SKEW
    base += SELFREG_SKEW;
#endif

#ifdef _WIN64
    const uintptr_t teb = __readgsqword(0x30);
#else
    const uintptr_t teb = __readfsdword(0x18);
#endif
    /* d = descriptor + 8, i.e. the image base field */
    volatile uint8_t* d = (volatile uint8_t*)(teb + (SELFREG_DESC_RVA + 8 - SELFREG_TEB_RVA));

    *(volatile uint32_t*)(d + 0) = (uint32_t)base; /* image base, low dword */
#ifdef _WIN64
    *(volatile uint32_t*)(d + 4) = (uint32_t)(base >> 32);
#endif
    *(volatile uint32_t*)(d + 8) = (uint32_t)(base + pdataRva); /* .pdata va, low */
#ifdef _WIN64
    *(volatile uint32_t*)(d + 12) = (uint32_t)((base + pdataRva) >> 32);
#endif
    *(volatile uint32_t*)(d + 16) = pdataSize; /* .pdata byte size */
    *(volatile uint32_t*)(d - 4) = resRva;     /* resource directory rva */
    *(volatile uint32_t*)(d - 8) = SELFREG_MAGIC; /* commit marker, written last */
}

#endif /* SELFREG_H */
