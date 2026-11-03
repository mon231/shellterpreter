#pragma once
#include <cstdint>
#include <cstring>
#include "fault.hpp"
#include "operand.hpp"

namespace stub {

// The shared instruction decoder. The modrm encoding carries the same bytes
// on both architectures but they mean different things: modrm.rm==5/mod==0
// is RIP+disp32 on x64 and plain disp32 on x86, and SIB disp32 is
// sign-extended on x64 but zero-extended on x86. decodeMR is arch-tagged so
// both cores decode from one implementation.

enum class Architecture { X64, X86 };

// byte/word fetch cursor over the image
struct Fetch {
    const uint8_t* data; size_t len; size_t pos;
    uint8_t u8() { return data[pos++]; }
    uint16_t u16() { uint16_t v; memcpy(&v, data + pos, 2); pos += 2; return v; }
    uint32_t u32() { uint32_t v; memcpy(&v, data + pos, 4); pos += 4; return v; }
    uint64_t u64() { uint64_t v; memcpy(&v, data + pos, 8); pos += 8; return v; }
};

// modrm/sib/displacement fields of one operand
struct MR {
    int mod = 3, reg = 0, rm = 0;
    bool hasSib = false;
    int sibBase = 0, sibIndex = 0, sibScale = 0;
    int64_t disp = 0;
    bool ripRel = false;  // x64: [rip+disp32]
    bool absDisp = false; // x86: [disp32]
};

uint64_t maskSz(int size);
unsigned bitsSz(int size);
uint64_t sext(int from, uint64_t value);
unsigned popcnt8(uint8_t value);

// a decoded modrm+displacement operand (arch-tagged)
template <Architecture architecture>
uint32_t decodeMR(Fetch& f, MR& m) {
    const uint8_t byte = f.u8();
    m.mod = byte >> 6;
    m.reg = (byte >> 3) & 7;
    m.rm = byte & 7;
    m.hasSib = false;
    m.ripRel = false;
    m.absDisp = false;
    m.disp = 0;
    if (m.mod == 3) return fault_code(Fault::None);
    if (m.rm == 4) {
        m.hasSib = true;
        const uint8_t sib = f.u8();
        m.sibScale = sib >> 6;
        m.sibIndex = (sib >> 3) & 7;
        m.sibBase = sib & 7;
        if (m.sibBase == 5 && m.mod == 0) {
            if constexpr (architecture == Architecture::X64) m.disp = static_cast<int32_t>(f.u32());
            else m.disp = static_cast<int64_t>(f.u32());
            return fault_code(Fault::None);
        }
        if (m.mod == 1) m.disp = static_cast<int8_t>(f.u8());
        else if (m.mod == 2) m.disp = static_cast<int32_t>(f.u32());
        return fault_code(Fault::None);
    }
    if (m.rm == 5 && m.mod == 0) {
        if constexpr (architecture == Architecture::X64) { m.ripRel = true; m.disp = static_cast<int32_t>(f.u32()); }
        else { m.absDisp = true; m.disp = static_cast<int64_t>(f.u32()); }
        return fault_code(Fault::None);
    }
    if (m.mod == 1) m.disp = static_cast<int8_t>(f.u8());
    else if (m.mod == 2) m.disp = static_cast<int32_t>(f.u32());
    return fault_code(Fault::None);
}

// condition code (cc = low 4 bits of jcc/setcc/cmov)
template <class EmuT>
bool cond(EmuT& e, uint8_t cc) {
    switch (cc & 0xF) {
    case 0x0: return e.of; case 0x1: return !e.of;
    case 0x2: return e.cf; case 0x3: return !e.cf;
    case 0x4: return e.zf; case 0x5: return !e.zf;
    case 0x6: return e.cf || e.zf; case 0x7: return !e.cf && !e.zf;
    case 0x8: return e.sf; case 0x9: return !e.sf;
    case 0xA: return e.pf; case 0xB: return !e.pf;
    case 0xC: return e.sf != e.of; case 0xD: return e.sf == e.of;
    case 0xE: return e.zf || (e.sf != e.of);
    default:  return !e.zf && (e.sf == e.of);
    }
}

// Read/write one decoded operand. Register operands go through EmuT.r[],
// memory operands through guest memory (memLd/memSt) and fail closed there.
template <class EmuT>
uint64_t operandRead(EmuT& e, const Operand& operand, int size, uint32_t& fault) {
    if (const OperandRegister* reg = std::get_if<OperandRegister>(&operand))
        return e.r[reg->index & 15] & maskSz(size);
    const OperandMemory& mem = std::get<OperandMemory>(operand);
    switch (size) {
    case 1: { uint8_t v; if (!memLd(e, mem.address, v)) { fault = fault_code(Fault::OutsideMemory); return 0; } return v; }
    case 2: { uint16_t v; if (!memLd(e, mem.address, v)) { fault = fault_code(Fault::OutsideMemory); return 0; } return v; }
    case 4: { uint32_t v; if (!memLd(e, mem.address, v)) { fault = fault_code(Fault::OutsideMemory); return 0; } return v; }
    case 8: { uint64_t v; if (!memLd(e, mem.address, v)) { fault = fault_code(Fault::OutsideMemory); return 0; } return v; }
    }
    fault = fault_code(Fault::UnsupportedInstruction); return 0;
}

template <class EmuT>
void operandWrite(EmuT& e, const Operand& operand, int size, uint64_t value, uint32_t& fault) {
    if (const OperandRegister* reg = std::get_if<OperandRegister>(&operand)) {
        if (size == 4) { e.r[reg->index & 15] = value & 0xFFFFFFFFull; return; }
        const uint64_t keep = ~maskSz(size);
        e.r[reg->index & 15] = (e.r[reg->index & 15] & keep) | (value & maskSz(size));
        return;
    }
    const OperandMemory& mem = std::get<OperandMemory>(operand);
    switch (size) {
    case 1: if (!memSt(e, mem.address, static_cast<uint8_t>(value))) fault = fault_code(Fault::OutsideMemory); break;
    case 2: if (!memSt(e, mem.address, static_cast<uint16_t>(value))) fault = fault_code(Fault::OutsideMemory); break;
    case 4: if (!memSt(e, mem.address, static_cast<uint32_t>(value))) fault = fault_code(Fault::OutsideMemory); break;
    case 8: if (!memSt(e, mem.address, value)) fault = fault_code(Fault::OutsideMemory); break;
    default: fault = fault_code(Fault::UnsupportedInstruction); break;
    }
}

} // namespace stub
