#pragma once
#include "vm.hpp"
#include "guest_environment.hpp"
#include "native_bridge.hpp"
#include "instruction_decoder.hpp"
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdint>

namespace stub {

constexpr uint64_t kInstrBudget = 5000000000ull;

// Per-run instruction cap, seeded from the SHELLTERP_BUDGET environment
// variable (defined once in cpu.cpp); invalid or zero values fall back.
uint64_t instructionBudget();

enum Reg {
    kRAX = 0, kRCX, kRDX, kRBX, kRSP, kRBP, kRSI, kRDI,
    kR8, kR9, kR10, kR11, kR12, kR13, kR14, kR15, kNumReg
};

// One CPU instance per architecture; the two cores merged into one template.
// Every place the real encodings differ is resolved by if constexpr on the
// template parameter (by design: these differences are compile-time facts,
// not runtime branches).
// Guest memory shared with the decoded-operand helpers in
// instruction_decoder.hpp: these free templates are found through
// argument-dependent lookup when operandRead/operandWrite are instantiated
// with the emulator state, so the Cpu class keeps one copy of the logic.
template <class T, class EmuT> uint8_t* addrPtr(EmuT& e, uint64_t addr) {
    // addr <= end before the addr+sizeof(T) <= end compare: that sum wraps for
    // addr near 2^64 and would hand memLd/memSt a wild host pointer otherwise
    if (addr >= e.l->img.base() && addr <= e.imgEnd && addr + sizeof(T) <= e.imgEnd)
        return e.l->img.data() + (addr - e.l->img.base());
    if (addr >= e.l->stk.base() && addr <= e.l->stk.base() + e.l->stk.size() && addr + sizeof(T) <= e.l->stk.base() + e.l->stk.size())
        return e.l->stk.data() + (addr - e.l->stk.base());
    if (addr >= e.envBase && addr <= e.envEnd && addr + sizeof(T) <= e.envEnd)
        return e.l->env.data() + (addr - e.envBase);
    if (addr >= e.l->heap.base() && addr <= e.l->heapEnd && addr + sizeof(T) <= e.l->heapEnd)
        return e.l->heap.data() + (addr - e.l->heap.base());
    for (uint32_t i = 0; i < e.l->threadCount; ++i) {
        const GuestRegion& stack = e.l->threads[i].stack;
        if (addr >= stack.base() && addr <= stack.base() + stack.size() && addr + sizeof(T) <= stack.base() + stack.size())
            return stack.data() + (addr - stack.base());
    }
    return nullptr;
}
template <class T, class EmuT> bool memLd(EmuT& e, uint64_t addr, T& out) {
    uint8_t* p = addrPtr<T>(e, addr);
    if (!p) {
        // whole-memory fallback: any committed, readable host page (batch D).
        // Covers memory real stand-ins hand out (VirtualAlloc results, live
        // module images). Writes stay restricted to writable pages.
        if (!hostPageAddr(addr, sizeof(T), false, p)) return false;
    }
    memcpy(&out, p, sizeof(T));
    return true;
}
template <class T, class EmuT> bool memSt(EmuT& e, uint64_t addr, T v) {
    uint8_t* p = addrPtr<T>(e, addr);
    if (!p) {
        if (!hostPageAddr(addr, sizeof(T), true, p)) return false;
    }
    memcpy(p, &v, sizeof(T));
    return true;
}

template <Architecture architecture> class Cpu {
private:
    static constexpr bool is64 = architecture == Architecture::X64;
    static constexpr int kXmmCount = is64 ? 16 : 8;

    struct Emu {
        uint64_t r[kNumReg] = {};
        // minimal 128-bit register file for SSE data movement
        // (movaps/movups/... on x64, movlpd/xorps on x86)
        uint64_t xmm[kXmmCount][2] = {};
        // minimal x87 stack: 8 doubles, TOP index and the compare condition
        // bits of a half status word (C0 bit 8, C1 bit 9, C2 bit 10, C3 bit 14)
        double x87St[8] = {};
        int fTop = 0;
        uint16_t fsw = 0;
        uint16_t fCw = 0x027F; // control word default; rounding treated as always-RNE
        uint64_t ip = 0;
        bool cf = false, of = false, sf = false, zf = false, pf = false, af = false, df = false;
        Loaded* l = nullptr;
        uint64_t imgEnd = 0, stkEnd = 0;
        uint64_t fsBase = 0, gsBase = 0, envBase = 0, envEnd = 0;
        uint64_t budget = kInstrBudget;
    };

    struct Ctx {
        Emu& e;
        Loaded& l;
        Fetch& f;
        int rexW = 0, rexR = 0, rexX = 0, rexB = 0;
        bool op66 = false, rexUsed = false;
        int segGs = 0, segFs = 0;
        bool rep = false, repF2 = false;
        uint32_t fault = fault_code(Fault::None);
        MR mr;
        Operand o{ OperandMemory{} };  // r/m operand after decodeRm
        Operand g{};                   // reg operand from modrm.reg
        bool ipSet = false;

        bool oIsReg() const { return std::holds_alternative<OperandRegister>(o); }
        uint8_t oRegIdx() const { return std::get<OperandRegister>(o).index; }
        uint64_t oAddr() const { return std::get<OperandMemory>(o).address; }
        uint8_t gRegIdx() const { return std::get<OperandRegister>(g).index; }

        void castSet(int idx, int sz, uint64_t v) {
            if (sz == 4) { e.r[idx & 15] = v & 0xFFFFFFFFull; return; }
            if (sz == 2) { e.r[idx & 15] = (e.r[idx & 15] & ~0xFFFFull) | (v & 0xFFFF); return; }
            e.r[idx & 15] = v;
        }
        int operSz() const { return is64 ? (op66 ? 2 : (rexW ? 8 : 4)) : (op66 ? 2 : 4); }

        uint32_t decodeRm() {
            if (fault != fault_code(Fault::None)) return fault;
            const uint32_t r = decodeMR<architecture>(f, mr);
            if (r != fault_code(Fault::None)) { fault = r; return r; }
            o = mr.mod == 3 ? Operand{ OperandRegister{ static_cast<uint8_t>(mr.rm | (rexB << 3)) } }
                            : Operand{ OperandMemory{} };
            g = Operand{ OperandRegister{ static_cast<uint8_t>(mr.reg | (rexR << 3)) } };
            return fault_code(Fault::None);
        }

        uint64_t eaCalc() {
            uint64_t ea = 0;
            if constexpr (is64) {
                if (mr.ripRel) {
                    ea = f.ipBase + f.pos + mr.disp;
                } else if (mr.hasSib) {
                    ea = 0;
                    if (!(mr.sibBase == 5 && mr.mod == 0)) ea += e.r[mr.sibBase | (rexB << 3)];
                    if (mr.sibIndex != 4) ea += e.r[mr.sibIndex | (rexX << 3)] << mr.sibScale;
                    ea += mr.disp;
                } else {
                    ea = e.r[mr.rm | (rexB << 3)] + mr.disp;
                }
                if (segGs) ea += e.gsBase;
            } else {
                if (mr.absDisp) {
                    ea = static_cast<uint64_t>(static_cast<uint32_t>(mr.disp));
                } else if (mr.hasSib) {
                    ea = 0;
                    if (!(mr.sibBase == 5 && mr.mod == 0)) ea += e.r[mr.sibBase | (rexB << 3)];
                    if (mr.sibIndex != 4) ea += e.r[mr.sibIndex | (rexX << 3)] << mr.sibScale;
                    ea += mr.disp;
                } else {
                    ea = e.r[mr.rm | (rexB << 3)] + mr.disp;
                }
                if (segFs) ea += e.fsBase;
            }
            return ea;
        }

        uint64_t oVal(int sz) {
            if (oIsReg()) return e.r[oRegIdx() & 15] & maskSz(sz);
            o = Operand{ OperandMemory{ eaCalc() } };
            return operandRead(e, o, sz, fault);
        }
        void oSet(int sz, uint64_t v) {
            if (!oIsReg()) o = Operand{ OperandMemory{ eaCalc() } };
            operandWrite(e, o, sz, v, fault);
        }
        uint64_t gVal(int sz) { return e.r[gRegIdx() & 15] & maskSz(sz); }
        void gSet(int sz, uint64_t v) {
            if (sz == 4) { e.r[gRegIdx() & 15] = v & 0xFFFFFFFFull; return; }
            const uint64_t keep = ~maskSz(sz);
            e.r[gRegIdx() & 15] = (e.r[gRegIdx() & 15] & keep) | (v & maskSz(sz));
        }

        uint64_t imm64(int sz, bool signImm8) {
            switch (sz) {
            case 1: { const uint8_t v = f.u8(); return signImm8 ? sext(1, v) : v; }
            case 2: { const uint16_t v = f.u16(); return v; }
            case 4: { const uint32_t v = f.u32(); return v; }
            case 8: {
                if constexpr (is64) {
                    if (signImm8) { const uint32_t v = f.u32(); return sext(4, v); }
                    const uint32_t lo = f.u32();
                    const uint32_t hi = f.u32();
                    return static_cast<uint64_t>(lo) | (static_cast<uint64_t>(hi) << 32);
                } else {
                    const uint32_t v = f.u32();
                    return signImm8 ? sext(4, v) : v;
                }
            }
            }
            fault = fault_code(Fault::UnsupportedInstruction); return 0;
        }

        uint64_t reg8Read(int idx) {
            const int r = idx & 15;
            if (r >= 4 && !rexUsed) return (e.r[r & 3] >> 8) & 0xFF;
            return e.r[r] & 0xFF;
        }
        void reg8Write(int idx, uint64_t v) {
            const int r = idx & 15;
            if (r >= 4 && !rexUsed) {
                e.r[r & 3] = (e.r[r & 3] & ~0xFF00ull) | ((v & 0xFF) << 8);
                return;
            }
            e.r[r] = (e.r[r] & ~0xFFull) | (v & 0xFF);
        }

        uint64_t o8Read() {
            if (oIsReg()) return reg8Read(oRegIdx());
            o = Operand{ OperandMemory{ eaCalc() } };
            uint8_t v; if (!memLd(e, oAddr(), v)) fault = fault_code(Fault::OutsideMemory);
            return v;
        }
        void o8Write(uint64_t v) {
            if (oIsReg()) { reg8Write(oRegIdx(), v); return; }
            o = Operand{ OperandMemory{ eaCalc() } };
            if (!memSt(e, oAddr(), static_cast<uint8_t>(v))) fault = fault_code(Fault::OutsideMemory);
        }
        uint64_t g8Read() { return reg8Read(gRegIdx()); }
        void g8Write(uint64_t v) { reg8Write(gRegIdx(), v); }
    };

    // ---- flags + ALU ----

    static void flagsLogic(Emu& e, int sz, uint64_t res) {
        e.cf = e.of = false;
        res &= maskSz(sz);
        e.zf = res == 0;
        e.sf = (res & (1ull << (bitsSz(sz) - 1))) != 0;
        e.pf = (popcnt8(static_cast<uint8_t>(res & 0xFF)) % 2) == 0;
    }
    static void flagsNZP(Emu& e, int sz, uint64_t res) {
        res &= maskSz(sz);
        e.zf = res == 0;
        e.sf = (res & (1ull << (bitsSz(sz) - 1))) != 0;
        e.pf = (popcnt8(static_cast<uint8_t>(res & 0xFF)) % 2) == 0;
    }
    static uint64_t doAdd(Emu& e, int sz, uint64_t a, uint64_t b) {
        const uint64_t sum = (a & maskSz(sz)) + (b & maskSz(sz));
        const uint64_t res = sum & maskSz(sz);
        e.cf = (sum >> bitsSz(sz)) != 0;
        const uint64_t sign = 1ull << (bitsSz(sz) - 1);
        e.of = (((a ^ res) & (b ^ res)) & sign) != 0;
        e.af = ((a ^ b ^ res) & 0x10) != 0;
        flagsLogic(e, sz, res);
        return res;
    }
    static uint64_t doSubF(Emu& e, int sz, uint64_t a, uint64_t b) {
        const uint64_t aa = a & maskSz(sz), bb = b & maskSz(sz);
        const uint64_t res = (aa - bb) & maskSz(sz);
        e.cf = aa < bb;
        const uint64_t sign = 1ull << (bitsSz(sz) - 1);
        e.of = (((aa ^ bb) & (aa ^ res)) & sign) != 0;
        e.af = ((aa ^ bb ^ res) & 0x10) != 0;
        flagsNZP(e, sz, res); // keep borrow in cf; flagsLogic would clear it
        return res;
    }
    static uint64_t doLogicOp(Emu& e, int sz, uint64_t res) { flagsLogic(e, sz, res); return res & maskSz(sz); }
    static uint64_t doIncOp(Emu& e, int sz, uint64_t a) { const bool c = e.cf; const uint64_t res = doAdd(e, sz, a, 1); e.cf = c; return res; }
    static uint64_t doDecOp(Emu& e, int sz, uint64_t a) { const bool c = e.cf; const uint64_t res = doSubF(e, sz, a, 1); e.cf = c; return res; }
    static uint64_t doNegOp(Emu& e, int sz, uint64_t a) {
        const uint64_t aa = a & maskSz(sz);
        const uint64_t res = (0 - aa) & maskSz(sz);
        e.cf = aa != 0;
        const uint64_t sign = 1ull << (bitsSz(sz) - 1);
        e.of = ((aa & sign) != 0) && ((res & sign) != 0);
        flagsLogic(e, sz, res);
        return res;
    }
    static uint64_t adcOp(Emu& e, int sz, uint64_t a, uint64_t b, uint64_t cf) {
        const uint64_t m = maskSz(sz);
        const uint64_t aa = a & m, bb = b & m;
        const uint64_t sum = aa + bb + cf;
        const uint64_t res = sum & m;
        e.cf = (sum >> bitsSz(sz)) != 0;
        const uint64_t sign = 1ull << (bitsSz(sz) - 1);
        e.of = (((aa ^ res) & (bb ^ res)) & sign) != 0;
        e.af = ((aa ^ bb ^ res) & 0x10) != 0;
        flagsNZP(e, sz, res);
        return res;
    }
    static uint64_t sbbOp(Emu& e, int sz, uint64_t a, uint64_t b, uint64_t cf) {
        const uint64_t m = maskSz(sz);
        const uint64_t aa = a & m, bb = b & m;
        const uint64_t total = bb + cf;
        const uint64_t res = (aa - total) & m;
        e.cf = aa < total || total < bb;
        const uint64_t sign = 1ull << (bitsSz(sz) - 1);
        e.of = (((aa ^ bb) & (aa ^ res)) & sign) != 0;
        e.af = ((aa ^ bb ^ res) & 0x10) != 0;
        flagsNZP(e, sz, res);
        return res;
    }
    static uint32_t aluOp(Ctx& c, int fam, uint64_t a, uint64_t b, int sz, uint64_t& out) {
        switch (fam) {
        case 0: out = doAdd(c.e, sz, a, b); return fault_code(Fault::None);
        case 1: out = doLogicOp(c.e, sz, a | b); return fault_code(Fault::None);
        case 2: out = adcOp(c.e, sz, a, b, c.e.cf ? 1 : 0); return fault_code(Fault::None);
        case 3: out = sbbOp(c.e, sz, a, b, c.e.cf ? 1 : 0); return fault_code(Fault::None);
        case 4: out = doLogicOp(c.e, sz, a & b); return fault_code(Fault::None);
        case 5: out = doSubF(c.e, sz, a, b); return fault_code(Fault::None);
        case 6: out = doLogicOp(c.e, sz, a ^ b); return fault_code(Fault::None);
        default: doSubF(c.e, sz, a, b); out = a; return fault_code(Fault::None);
        }
    }
    static int64_t mulSigned(int sz, uint64_t a, uint64_t b, int& ovf) {
        ovf = 0;
        switch (sz) {
        case 1: { const int64_t v = static_cast<int64_t>(static_cast<int8_t>(a & 0xFF)) * static_cast<int64_t>(static_cast<int8_t>(b & 0xFF)); ovf = (v != static_cast<int64_t>(static_cast<int8_t>(v & 0xFF))); return v; }
        case 2: { const int64_t v = static_cast<int64_t>(static_cast<int16_t>(a & 0xFFFF)) * static_cast<int64_t>(static_cast<int16_t>(b & 0xFFFF)); ovf = (v != static_cast<int64_t>(static_cast<int16_t>(v & 0xFFFF))); return v; }
        case 4: { const int64_t v = static_cast<int64_t>(static_cast<int32_t>(a & 0xFFFFFFFFull)) * static_cast<int64_t>(static_cast<int32_t>(b & 0xFFFFFFFFull)); ovf = (v != static_cast<int64_t>(static_cast<int32_t>(v & 0xFFFFFFFFull))); return v; }
        default: {
            const int64_t v = static_cast<int64_t>(a) * static_cast<int64_t>(b);
            ovf = (((a ^ static_cast<uint64_t>(v)) & (b ^ static_cast<uint64_t>(v))) >> 63) != 0;
            return v;
        }
        }
    }

    // q must fit 64 bits (caller must not call when hi >= d); remainder always < d
    static uint64_t div128u(uint64_t hi, uint64_t lo, uint64_t d, uint64_t& rem) {
        uint64_t rHi = 0, rLo = 0, qLo = 0;
        for (int i = 127; i >= 0; --i) {
            const uint64_t bit = (i >= 64) ? ((hi >> (i - 64)) & 1) : ((lo >> i) & 1);
            rHi = (rHi << 1) | (rLo >> 63);
            rLo = (rLo << 1) | bit;
            const bool can = rHi != 0 || rLo >= d;
            if (can) {
                if (rLo >= d) rLo -= d;
                else { --rHi; rLo -= d; }
            }
            qLo = (qLo << 1) | (can ? 1 : 0);
        }
        rem = rLo;
        return qLo;
    }
    static void neg128(uint64_t& hi, uint64_t& lo) {
        const uint64_t nl = ~lo + 1;
        hi = ~hi + (lo == 0);
        lo = nl;
    }

    // full 64x64 -> 128 unsigned multiply, portable (x86 has no _umul128)
    static void mul64u(uint64_t a, uint64_t b, uint64_t& hi, uint64_t& lo) {
        const uint64_t a0 = a & 0xFFFFFFFFull, a1 = a >> 32;
        const uint64_t b0 = b & 0xFFFFFFFFull, b1 = b >> 32;
        const uint64_t p00 = a0 * b0, p01 = a0 * b1, p10 = a1 * b0, p11 = a1 * b1;
        const uint64_t mid = p10 + (p00 >> 32) + (p01 & 0xFFFFFFFFull);
        lo = (mid << 32) | (p00 & 0xFFFFFFFFull);
        hi = p11 + (mid >> 32) + (p01 >> 32);
    }

    // ---- SSE helpers (batch B) ----
    // prefix kinds: 0 = none/ps (2x f32), 1 = F3/ss, 2 = 66/pd (2x f64), 3 = F2/sd
    static uint64_t dto(double d) { uint64_t b; memcpy(&b, &d, 8); return b; }
    static double dfrom(uint64_t b) { double d; memcpy(&d, &b, 8); return d; }
    static uint32_t fto(float f) { uint32_t b; memcpy(&b, &f, 4); return b; }
    static float ffrom(uint32_t b) { float f; memcpy(&f, &b, 4); return f; }

    // xmm source for a packed/scalar op: mem forms load only the operand size
    // the real instruction reads (upper destination lanes stay untouched)
    static bool sseSrc(Ctx& c, uint64_t src[2], int kind) {
        if (c.oIsReg()) {
            const int s = (c.mr.rm | (c.rexB << 3)) & 15;
            src[0] = c.e.xmm[s][0];
            src[1] = c.e.xmm[s][1];
            return true;
        }
        const uint64_t ea = c.eaCalc();
        if (kind == 1) { uint32_t t = 0; if (!memLd(c.e, ea, t)) return false; src[0] = t; src[1] = 0; return true; }
        if (kind == 0 || kind == 3) { uint64_t t = 0; if (!memLd(c.e, ea, t)) return false; src[0] = t; src[1] = 0; return true; }
        return memLd<uint64_t>(c.e, ea, src[0]) && memLd<uint64_t>(c.e, ea + 8, src[1]);
    }

    // binary packed/scalar float family: add/sub/mul/div/min/max/sqrt/rcp/rsqrt
    // + bitwise and/andn/or/xor. Scalar kinds touch only the lowest element.
    static uint32_t sseBin(Ctx& c, uint8_t op2) {
        const int kind = c.repF2 ? 3 : c.rep ? 1 : c.op66 ? 2 : 0;
        c.decodeRm();
        if (c.fault != fault_code(Fault::None)) return c.fault;
        const int dst = c.gRegIdx() & 15;
        uint64_t src[2] = { 0, 0 };
        if (!sseSrc(c, src, kind)) { c.fault = fault_code(Fault::OutsideMemory); return c.fault; }
        const uint64_t d0 = c.e.xmm[dst][0], d1 = c.e.xmm[dst][1];
        if (op2 == 0x54 || op2 == 0x55 || op2 == 0x56 || op2 == 0x57) {
            // bitwise: full 128-bit operation regardless of prefix (xorps with a
            // dirty upper half must still produce zeros, like real hardware)
            const uint64_t mLo = ~0ull;
            const uint64_t s0 = src[0], dd0 = d0;
            uint64_t r0;
            if (op2 == 0x54) r0 = dd0 & s0;
            else if (op2 == 0x55) r0 = (~dd0) & s0; // andnps: dst = ~dst & src
            else if (op2 == 0x56) r0 = dd0 | s0;
            else r0 = dd0 ^ s0;
            c.e.xmm[dst][0] = r0;
            c.e.xmm[dst][1] = (op2 == 0x54) ? (d1 & src[1]) : (op2 == 0x55) ? ((~d1) & src[1]) : (op2 == 0x56) ? (d1 | src[1]) : (d1 ^ src[1]);
            return fault_code(Fault::None);
        }
        const int ln = (kind == 0 || kind == 2) ? 2 : 1;
        uint64_t res[2] = { d0, d1 };
        for (int i = 0; i < ln; ++i) {
            if (kind < 2) {
                const uint32_t sb = static_cast<uint32_t>(src[0] >> (32 * i));
                uint32_t r;
                switch (op2) {
                case 0x51: r = fto(sqrtf(ffrom(sb))); break;
                case 0x52: r = fto(1.0f / sqrtf(ffrom(sb))); break;
                case 0x53: r = fto(1.0f / ffrom(sb)); break;
                case 0x58: r = fto(ffrom(static_cast<uint32_t>(d0 >> (32 * i))) + ffrom(sb)); break;
                case 0x59: r = fto(ffrom(static_cast<uint32_t>(d0 >> (32 * i))) * ffrom(sb)); break;
                case 0x5C: r = fto(ffrom(static_cast<uint32_t>(d0 >> (32 * i))) - ffrom(sb)); break;
                case 0x5E: r = fto(ffrom(static_cast<uint32_t>(d0 >> (32 * i))) / ffrom(sb)); break;
                case 0x5D: r = fto(fminf(ffrom(static_cast<uint32_t>(d0 >> (32 * i))), ffrom(sb))); break;
                case 0x5F: r = fto(fmaxf(ffrom(static_cast<uint32_t>(d0 >> (32 * i))), ffrom(sb))); break;
                default: return fault_code(Fault::UnsupportedInstruction);
                }
                res[0] = (res[0] & ~(0xFFFFFFFFull << (32 * i))) | (static_cast<uint64_t>(r) << (32 * i));
            } else {
                const double b = dfrom(src[i]);
                const double a = dfrom(res[i]);
                double r;
                switch (op2) {
                case 0x51: r = sqrt(b); break;
                case 0x52: r = 1.0 / sqrt(b); break;
                case 0x53: r = 1.0 / b; break;
                case 0x58: r = a + b; break;
                case 0x59: r = a * b; break;
                case 0x5C: r = a - b; break;
                case 0x5E: r = a / b; break;
                case 0x5D: r = fmin(a, b); break;
                case 0x5F: r = fmax(a, b); break;
                default: return fault_code(Fault::UnsupportedInstruction);
                }
                res[i] = dto(r);
            }
        }
        c.e.xmm[dst][0] = res[0];
        if (kind == 2) c.e.xmm[dst][1] = res[1];
        return fault_code(Fault::None);
    }

    // cvt group: 0F 5A/5B/E6 (float<->int, ps<->pd); kind = sse prefix kind by op2
    //   5A: ps->pd (none), ss->sd (F3), sd->ss (F2), pd->ps (66)
    //   5B: dq->ps (none), ps->dq round (66), ps->dq trunc (F3)
    //   E6: dq->pd (F2), pd->dq round (66), pd->dq trunc (F3)
    static uint32_t sseCvtFlt(Ctx& c, uint8_t op2) {
        const int kind = c.repF2 ? 3 : c.rep ? 1 : c.op66 ? 2 : 0;
        c.decodeRm();
        if (c.fault != fault_code(Fault::None)) return c.fault;
        const int dst = c.gRegIdx() & 15;
        uint64_t src[2];
        if (!sseSrc(c, src, kind)) { c.fault = fault_code(Fault::OutsideMemory); return c.fault; }
        const uint64_t d0 = c.e.xmm[dst][0];
        switch (op2) {
        case 0x5A: {
            if (kind == 0) { // ps -> pd
                c.e.xmm[dst][0] = dto(static_cast<double>(ffrom(static_cast<uint32_t>(src[0]))));
                c.e.xmm[dst][1] = dto(static_cast<double>(ffrom(static_cast<uint32_t>(src[0] >> 32))));
            } else if (kind == 2) { // pd -> ps
                const uint32_t lo = fto(dfrom(src[0]));
                const uint32_t hi = fto(dfrom(src[1]));
                c.e.xmm[dst][0] = static_cast<uint64_t>(lo) | (static_cast<uint64_t>(hi) << 32);
            } else if (kind == 1) { // ss -> sd
                c.e.xmm[dst][0] = dto(static_cast<double>(ffrom(static_cast<uint32_t>(src[0]))));
            } else { // sd -> ss
                c.e.xmm[dst][0] = (d0 & ~0xFFFFFFFFull) | fto(dfrom(src[0]));
            }
            return fault_code(Fault::None);
        }
        case 0x5B: {
            if (kind == 0) { // dq2ps
                const float a = static_cast<float>(static_cast<int32_t>(src[0]));
                const float b = static_cast<float>(static_cast<int32_t>(src[0] >> 32));
                c.e.xmm[dst][0] = static_cast<uint64_t>(fto(a)) | (static_cast<uint64_t>(fto(b)) << 32);
            } else if (kind == 2) { // ps2dq round; dst upper zero
                const int32_t a = static_cast<int32_t>(lrintf(ffrom(static_cast<uint32_t>(src[0]))));
                const int32_t b = static_cast<int32_t>(lrintf(ffrom(static_cast<uint32_t>(src[0] >> 32))));
                c.e.xmm[dst][0] = static_cast<uint64_t>(static_cast<uint32_t>(a)) |
                                  (static_cast<uint64_t>(static_cast<uint32_t>(b)) << 32);
                c.e.xmm[dst][1] = 0;
            } else if (kind == 1) { // cvttps2dq trunc; dst upper zero
                const int32_t a = static_cast<int32_t>(ffrom(static_cast<uint32_t>(src[0])));
                const int32_t b = static_cast<int32_t>(ffrom(static_cast<uint32_t>(src[0] >> 32)));
                c.e.xmm[dst][0] = static_cast<uint64_t>(static_cast<uint32_t>(a)) |
                                  (static_cast<uint64_t>(static_cast<uint32_t>(b)) << 32);
                c.e.xmm[dst][1] = 0;
            } else return fault_code(Fault::UnsupportedInstruction);
            return fault_code(Fault::None);
        }
        case 0xE6: {
            if (kind == 3) { // dq2pd: 2 s32 lanes -> 2 f64
                c.e.xmm[dst][0] = dto(static_cast<double>(static_cast<int32_t>(src[0])));
                c.e.xmm[dst][1] = dto(static_cast<double>(static_cast<int32_t>(src[0] >> 32)));
            } else if (kind == 2) { // pd2dq round; low lane kept, upper zero
                c.e.xmm[dst][0] = static_cast<uint64_t>(static_cast<uint32_t>(static_cast<int32_t>(lrint(dfrom(src[0])))));
                c.e.xmm[dst][1] = 0;
            } else if (kind == 1) { // cvttpd2dq trunc
                c.e.xmm[dst][0] = static_cast<uint64_t>(static_cast<uint32_t>(static_cast<int32_t>(dfrom(src[0]))));
                c.e.xmm[dst][1] = 0;
            } else return fault_code(Fault::UnsupportedInstruction);
            return fault_code(Fault::None);
        }
        default: return fault_code(Fault::UnsupportedInstruction);
        }
    }

    // 0F 2A (si -> ss/sd with F3/F2) and 0F 2C/2D (ss/sd -> si with F3/F2)
    // The GPR source is signed; x64 REX.W stays 64-bit. Out-of-range float->int
    // is hardware "integer indefinite" (INT_MIN) - never guessed otherwise.
    static uint32_t sseCvtInt(Ctx& c, uint8_t op2) {
        if (op2 != 0x2A && !(c.rep || c.repF2)) return fault_code(Fault::UnsupportedInstruction);
        const int fkind = c.repF2 ? 3 : 1; // ss or sd
        c.decodeRm();
        if (c.fault != fault_code(Fault::None)) return c.fault;
        if (op2 == 0x2A) {
            const int dst = c.gRegIdx() & 15;
            const int isz = (c.rexW && is64) ? 8 : 4;
            const int64_t sv = (isz == 8) ? static_cast<int64_t>(c.oVal(8)) : static_cast<int32_t>(c.oVal(4));
            if (c.fault != fault_code(Fault::None)) return c.fault;
            if (c.repF2) c.e.xmm[dst][0] = dto(static_cast<double>(sv));
            else c.e.xmm[dst][0] = (c.e.xmm[dst][0] & ~0xFFFFFFFFull) | fto(static_cast<float>(sv));
            return fault_code(Fault::None);
        }
        uint64_t src[2];
        if (!sseSrc(c, src, fkind)) { c.fault = fault_code(Fault::OutsideMemory); return c.fault; }
        const double v = (fkind == 1) ? static_cast<double>(ffrom(static_cast<uint32_t>(src[0]))) : dfrom(src[0]);
        const int osz = (c.rexW && is64) ? 8 : 4;
        const double lo = (osz == 4) ? -2147483648.0 : -9223372036854775808.0;
        const double hi = (osz == 4) ? 2147483648.0 : 9223372036854775808.0;
        const bool bad = !(v >= lo && v < hi);
        if (bad) {
            // integer indefinite: INT32_MIN for a 32-bit destination
            c.gSet(osz, (osz == 4) ? 0x80000000ull : 0x8000000000000000ull);
            if (c.fault != fault_code(Fault::None)) return c.fault;
            return fault_code(Fault::None);
        }
        const int64_t iv = (op2 == 0x2C) ? static_cast<int64_t>(v) : static_cast<int64_t>(llrint(v)); // truncate toward zero
        c.gSet(osz, static_cast<uint64_t>(iv) & maskSz(osz));
        if (c.fault != fault_code(Fault::None)) return c.fault;
        return fault_code(Fault::None);
    }

    // xmm dst/src(128) generic read: reg or full 16 bytes of memory
    static bool sseSrc128(Ctx& c, uint64_t src[2]) {
        if (c.oIsReg()) {
            const int s = (c.mr.rm | (c.rexB << 3)) & 15;
            src[0] = c.e.xmm[s][0];
            src[1] = c.e.xmm[s][1];
            return true;
        }
        const uint64_t ea = c.eaCalc();
        return memLd<uint64_t>(c.e, ea, src[0]) && memLd<uint64_t>(c.e, ea + 8, src[1]);
    }

    // unpcklps/hps (none) and unpcklpd/hpd (66)
    static uint32_t sseUnpck(Ctx& c, uint8_t op2) {
        c.decodeRm();
        if (c.fault != fault_code(Fault::None)) return c.fault;
        const int dst = c.gRegIdx() & 15;
        uint64_t s[2];
        if (!sseSrc128(c, s)) { c.fault = fault_code(Fault::OutsideMemory); return c.fault; }
        const uint64_t d0 = c.e.xmm[dst][0], d1 = c.e.xmm[dst][1];
        if (c.op66) {
            c.e.xmm[dst][0] = (op2 == 0x14) ? d0 : d1;
            c.e.xmm[dst][1] = (op2 == 0x14) ? s[0] : s[1];
        } else {
            if (op2 == 0x14) c.e.xmm[dst][0] = (d0 & 0xFFFFFFFFull) | ((s[0] & 0xFFFFFFFFull) << 32);
            else c.e.xmm[dst][0] = (d0 & 0xFFFFFFFF00000000ull) | (s[0] & 0xFFFFFFFFull);
            if (op2 == 0x14) c.e.xmm[dst][1] = (d0 & 0xFFFFFFFF00000000ull) | (s[0] & 0xFFFFFFFF00000000ull);
            else c.e.xmm[dst][1] = (d1 & 0xFFFFFFFF00000000ull) | (s[1] & 0xFFFFFFFF00000000ull);
        }
        return fault_code(Fault::None);
    }

    // cmpps/cmpss/cmppd/cmpsd with imm8 predicate 0..7 (dst vs src)
    static uint32_t sseCmp(Ctx& c) {
        const int kind = c.repF2 ? 3 : c.rep ? 1 : c.op66 ? 2 : 0;
        c.decodeRm();
        if (c.fault != fault_code(Fault::None)) return c.fault;
        const int dst = c.gRegIdx() & 15;
        uint64_t src[2];
        if (!sseSrc(c, src, kind)) { c.fault = fault_code(Fault::OutsideMemory); return c.fault; }
        const int pred = c.f.u8() & 7;
        const int ln = (kind == 0 || kind == 2) ? 2 : 1;
        uint64_t res[2] = { c.e.xmm[dst][0], c.e.xmm[dst][1] };
        for (int i = 0; i < ln; ++i) {
            bool ok;
            if (kind < 2) {
                const float a = ffrom(static_cast<uint32_t>(res[i] >> (32 * i)));
                const float b = ffrom(static_cast<uint32_t>(src[0] >> (32 * i)));
                ok = (pred == 0) ? a == b : (pred == 1) ? a < b : (pred == 2) ? a <= b
                     : (pred == 3) ? (isnan(a) || isnan(b)) : (pred == 4) ? !(a == b)
                     : (pred == 5) ? !(a < b) : (pred == 6) ? !(a <= b) : !(isnan(a) || isnan(b));
            } else {
                const double a = dfrom(res[i]);
                const double b = dfrom(src[i]);
                ok = (pred == 0) ? a == b : (pred == 1) ? a < b : (pred == 2) ? a <= b
                     : (pred == 3) ? (isnan(a) || isnan(b)) : (pred == 4) ? !(a == b)
                     : (pred == 5) ? !(a < b) : (pred == 6) ? !(a <= b) : !(isnan(a) || isnan(b));
            }
            const uint64_t w = (kind < 2) ? 0xFFFFFFFFull : ~0ull;
            res[i] = ok ? (res[i] | w) : (res[i] & ~w);
        }
        c.e.xmm[dst][0] = res[0];
        if (kind == 2) c.e.xmm[dst][1] = res[1];
        return fault_code(Fault::None);
    }

    // shufps/shufpd with imm8
    static uint32_t sseShuf(Ctx& c) {
        c.decodeRm();
        if (c.fault != fault_code(Fault::None)) return c.fault;
        const int dst = c.gRegIdx() & 15;
        uint64_t s[2];
        if (!sseSrc128(c, s)) { c.fault = fault_code(Fault::OutsideMemory); return c.fault; }
        const int imm = c.f.u8();
        const uint64_t d0 = c.e.xmm[dst][0], d1 = c.e.xmm[dst][1];
        if (c.op66) { // shufpd: 2 lanes
            c.e.xmm[dst][0] = (imm & 1) ? d0 : s[0];
            c.e.xmm[dst][1] = (imm & 2) ? d1 : s[1];
            return fault_code(Fault::None);
        }
        const uint32_t dw[2][4] = {
            { static_cast<uint32_t>(d0), static_cast<uint32_t>(d0 >> 32), static_cast<uint32_t>(d1), static_cast<uint32_t>(d1 >> 32) },
            { static_cast<uint32_t>(s[0]), static_cast<uint32_t>(s[0] >> 32), static_cast<uint32_t>(s[1]), static_cast<uint32_t>(s[1] >> 32) },
        };
        const uint32_t r0 = dw[1][imm & 3], r1 = dw[1][(imm >> 2) & 3], r2 = dw[0][(imm >> 4) & 3], r3 = dw[0][imm >> 6];
        c.e.xmm[dst][0] = static_cast<uint64_t>(r0) | (static_cast<uint64_t>(r1) << 32);
        c.e.xmm[dst][1] = static_cast<uint64_t>(r2) | (static_cast<uint64_t>(r3) << 32);
        return fault_code(Fault::None);
    }

    // pshufd (66), pshuflw (F3), pshufhw (F2), pshufw (NP, mmx) with imm8
    static uint32_t ssePshuf(Ctx& c) {
        c.decodeRm();
        if (c.fault != fault_code(Fault::None)) return c.fault;
        const int dst = c.gRegIdx() & 15;
        uint64_t s[2];
        if (c.oIsReg()) {
            const int sr = (c.mr.rm | (c.rexB << 3)) & 15;
            s[0] = c.e.xmm[sr][0];
            s[1] = c.e.xmm[sr][1];
        } else {
            const uint64_t ea = c.eaCalc();
            if (!memLd<uint64_t>(c.e, ea, s[0])) { c.fault = fault_code(Fault::OutsideMemory); return c.fault; }
            if (c.op66) {
                if (!memLd<uint64_t>(c.e, ea + 8, s[1])) { c.fault = fault_code(Fault::OutsideMemory); return c.fault; }
            } else s[1] = 0;
        }
        const int imm = c.f.u8();
        if (c.op66) { // pshufd over 4 dwords
            const uint32_t w[4] = { static_cast<uint32_t>(s[0]), static_cast<uint32_t>(s[0] >> 32), static_cast<uint32_t>(s[1]), static_cast<uint32_t>(s[1] >> 32) };
            c.e.xmm[dst][0] = static_cast<uint64_t>(w[imm & 3]) | (static_cast<uint64_t>(w[(imm >> 2) & 3]) << 32);
            c.e.xmm[dst][1] = static_cast<uint64_t>(w[(imm >> 4) & 3]) | (static_cast<uint64_t>(w[(imm >> 6) & 3]) << 32);
        } else if (c.repF2) { // pshufhw: high 4 words from s[1]
            uint64_t v = 0;
            for (int i = 0; i < 4; ++i)
                v |= ((s[1] >> (16 * ((imm >> (2 * i)) & 3))) & 0xFFFFull) << (16 * i);
            c.e.xmm[dst][1] = v;
        } else { // pshuflw / pshufw: low 4 words from s[0]
            uint64_t v = 0;
            for (int i = 0; i < 4; ++i)
                v |= ((s[0] >> (16 * ((imm >> (2 * i)) & 3))) & 0xFFFFull) << (16 * i);
            c.e.xmm[dst][0] = v;
            if (!c.rep) c.e.xmm[dst][1] = 0; // pshufw (mmx) clears the upper half
        }
        return fault_code(Fault::None);
    }

    // scalar lane shift used by the 71/72 word/dword groups
    static uint64_t pshLane16(uint64_t w, uint64_t k, int sel) {
        const uint16_t v = static_cast<uint16_t>(w & 0xFFFFull);
        if (sel == 6) return k >= 16 ? 0 : static_cast<uint64_t>(static_cast<uint16_t>(v << k));
        if (sel == 2) return k >= 16 ? 0 : static_cast<uint64_t>(v >> k);
        const int16_t sv = static_cast<int16_t>(v);
        const int32_t r = k >= 16 ? (sv < 0 ? -1 : 0) : (sv >> static_cast<int>(k));
        return static_cast<uint64_t>(static_cast<uint16_t>(r));
    }

    // 66/NP 0F 71 (words), 72 (dwords), 73 (quad/byte whole-register) shifts
    static uint32_t ssePShift(Ctx& c, uint8_t op2) {
        c.decodeRm();
        if (c.fault != fault_code(Fault::None)) return c.fault;
        // 0F 71/72/73: dst is the rm field; reg field is the shift subtype
        const int dst = (c.mr.rm | (c.rexB << 3)) & 15;
        const int sel = c.mr.reg & 7;
        const uint64_t count = static_cast<uint8_t>(c.f.u8());
        uint64_t v[2] = { c.e.xmm[dst][0], c.e.xmm[dst][1] };
        if (op2 == 0x71) {
            if (sel != 2 && sel != 4 && sel != 6) return fault_code(Fault::UnsupportedInstruction);
            for (int i = 0; i < 8; ++i) {
                const uint64_t w = pshLane16(i < 4 ? v[0] >> (16 * i) : v[1] >> (16 * (i - 4)), count, sel);
                if (i < 4) v[0] = (v[0] & ~(0xFFFFull << (16 * i))) | (w << (16 * i));
                else v[1] = (v[1] & ~(0xFFFFull << (16 * (i - 4)))) | (w << (16 * (i - 4)));
            }
        } else if (op2 == 0x72) {
            if (sel != 2 && sel != 4 && sel != 6) return fault_code(Fault::UnsupportedInstruction);
            const uint64_t k = count > 31 ? 32 : count;
            for (int i = 0; i < 4; ++i) {
                const uint64_t dw = (i < 2 ? v[0] >> (32 * i) : v[1] >> (32 * (i - 2)));
                uint64_t r = 0;
                if (sel == 6) r = k >= 32 ? 0 : (dw << k) & 0xFFFFFFFFull;
                else if (sel == 2) r = k >= 32 ? 0 : dw >> k;
                else {
                    const int64_t sv = static_cast<int64_t>(static_cast<int32_t>(dw & 0xFFFFFFFFull));
                    const int64_t ar = k >= 32 ? (sv < 0 ? -1 : 0) : sv >> static_cast<int>(k);
                    r = static_cast<uint64_t>(ar) & 0xFFFFFFFFull;
                }
                if (i < 2) v[0] = (v[0] & ~(0xFFFFFFFFull << (32 * i))) | (r << (32 * i));
                else v[1] = (v[1] & ~(0xFFFFFFFFull << (32 * (i - 2)))) | (r << (32 * (i - 2)));
            }
        } else { // 0x73
            if (sel == 6) { // psllq: both qword lanes shift left independently
                const uint64_t k = count > 63 ? 64 : count;
                if (k >= 64) v[0] = v[1] = 0;
                else { v[0] = v[0] << k; v[1] = c.op66 ? (v[1] << k) : 0; }
            } else if (sel == 2) { // psrlq: both qword lanes shift right independently
                const uint64_t k = count > 63 ? 64 : count;
                if (k >= 64) v[0] = v[1] = 0;
                else { v[0] = v[0] >> k; v[1] = c.op66 ? (v[1] >> k) : 0; }
            } else if (sel == 7 && c.op66) { // pslldq: byte shift left over 128 bits (66 only)
                const uint64_t k = count > 15 ? 16 : count;
                const uint64_t L = v[0], H = v[1];
                v[0] = k < 8 ? (L << (8 * k)) : 0;
                v[1] = k == 0 ? H : k < 8 ? ((H << (8 * k)) | (L >> (64 - 8 * k))) : k == 8 ? L : 0;
            } else if (sel == 3 && c.op66) { // psrldq
                const uint64_t k = count > 15 ? 16 : count;
                const uint64_t L = v[0], H = v[1];
                v[0] = k == 0 ? L : k < 8 ? ((L >> (8 * k)) | (H << (64 - 8 * k))) : k == 8 ? H : (H >> (8 * (k - 8)));
                v[1] = k < 8 ? (H >> (8 * k)) : 0;
            } else return fault_code(Fault::UnsupportedInstruction);
        }
        if (!c.op66) v[1] = 0; // mmx forms live in the low 64 bits only
        c.e.xmm[dst][0] = v[0];
        c.e.xmm[dst][1] = v[1];
        return fault_code(Fault::None);
    }

    // movd/movq GPR<->xmm/mmx: 0F 6E (mmx/66+REX load), 0F 7E (r/m store;
    // F3 0F 7E is the SSE2 movq load), 66 0F D6 (movq store + reg,reg move
    // that clears the upper half)
    static uint32_t sseMoveDQ(Ctx& c, uint8_t op2) {
        if (op2 == 0xD6 && !c.op66) return fault_code(Fault::UnsupportedInstruction);
        if (op2 == 0x7E && c.repF2) return fault_code(Fault::UnsupportedInstruction);
        const bool toXmm = (op2 == 0x6E) || (op2 == 0x7E && c.rep);
        const bool isQ = (op2 == 0xD6) || (op2 == 0x7E && c.rep);
        const bool use64 = ((c.rexW && is64 && c.op66) || isQ);
        c.decodeRm();
        if (c.fault != fault_code(Fault::None)) return c.fault;
        if (toXmm) {
            const int dst = c.gRegIdx() & 15;
            const uint64_t v = c.oVal(use64 ? 8 : 4);
            if (c.fault != fault_code(Fault::None)) return c.fault;
            c.e.xmm[dst][0] = v;
            if (use64) c.e.xmm[dst][1] = 0;
            return fault_code(Fault::None);
        }
        // source is the xmm/mmx reg; destination r/m (GPR/mem)
        const int src = (c.mr.reg | (c.rexR << 3)) & 15;
        if (c.oIsReg()) {
            c.castSet((c.mr.rm | (c.rexB << 3)) & 15, use64 ? 8 : 4, c.e.xmm[src][0]);
        } else {
            const uint64_t ea = c.eaCalc();
            if (use64) { if (!memSt<uint64_t>(c.e, ea, c.e.xmm[src][0])) { c.fault = fault_code(Fault::OutsideMemory); return c.fault; } }
            else if (!memSt(c.e, ea, static_cast<uint32_t>(c.e.xmm[src][0]))) { c.fault = fault_code(Fault::OutsideMemory); return c.fault; }
        }
        return fault_code(Fault::None);
    }

    // mmx padd/psub families (NP = 8-byte mmx, 66 for paddq only) on the
    // 64-bit low lane of the xmm register file
    static uint32_t ssePaddSub(Ctx& c, uint8_t op2) {
        c.decodeRm();
        if (c.fault != fault_code(Fault::None)) return c.fault;
        const int dst = c.mr.reg & 7;
        const int srcI = c.mr.rm & 7;
        uint64_t s = 0;
        if (c.oIsReg()) s = c.e.xmm[srcI][0];
        else {
            const uint64_t ea = c.eaCalc();
            if (!memLd<uint64_t>(c.e, ea, s)) { c.fault = fault_code(Fault::OutsideMemory); return c.fault; }
        }
        const uint64_t d = c.e.xmm[dst][0];
        uint64_t r = 0;
        if (op2 == 0xFC || op2 == 0xFE || op2 == 0xFD || op2 == 0xD4) { // add b/w/d/q
            const int es = (op2 == 0xFC) ? 1 : (op2 == 0xFE) ? 4 : (op2 == 0xFD) ? 2 : 8;
            for (int i = 0; i < 64 / (8 * es); ++i) {
                const uint64_t e = 8 * es;
                const uint64_t mask = (1ull << e) - 1;
                if (es == 8) r = d + s; // full 64
                else {
                    const uint64_t a = (d >> (e * i)) & mask, b = (s >> (e * i)) & mask;
                    r |= ((a + b) & mask) << (e * i);
                }
            }
        } else { // psub b/w/d/q: FB/F8/F9/FA
            const int es = (op2 == 0xF8) ? 1 : (op2 == 0xFB) ? 4 : (op2 == 0xF9) ? 2 : 8;
            for (int i = 0; i < 64 / (8 * es); ++i) {
                const uint64_t e = 8 * es;
                const uint64_t mask = (1ull << e) - 1;
                if (es == 8) r = d - s;
                else {
                    const uint64_t a = (d >> (e * i)) & mask, b = (s >> (e * i)) & mask;
                    r |= ((a - b) & mask) << (e * i);
                }
            }
        }
        c.e.xmm[dst][0] = r;
        return fault_code(Fault::None);
    }

    // pinsrw (0F C4)/pextrw (0F C5): word insert/extract with imm8 index
    static uint32_t ssePinEx(Ctx& c, uint8_t op2) {
        c.decodeRm();
        if (c.fault != fault_code(Fault::None)) return c.fault;
        const int idx = c.f.u8() & 7;
        if (op2 == 0xC4) { // pinsrw xmm/ mm, r32/m16
            const int dst = c.gRegIdx() & 15;
            const uint64_t v = c.oVal(2);
            if (c.fault != fault_code(Fault::None)) return c.fault;
            uint64_t lo = c.e.xmm[dst][0];
            lo = (lo & ~(0xFFFFull << (16 * idx))) | ((v & 0xFFFFull) << (16 * idx));
            c.e.xmm[dst][0] = lo;
            return fault_code(Fault::None);
        }
        // pextrw r32, xmm/mm
        const int dst = c.gRegIdx() & 15;
        uint64_t v = 0;
        if (c.oIsReg()) {
            const int s = (c.mr.rm | (c.rexB << 3)) & 15;
            v = (c.e.xmm[s][0] >> (16 * idx)) & 0xFFFFull;
        } else {
            const uint64_t ea = c.eaCalc();
            if (!memLd<uint64_t>(c.e, ea, v)) { c.fault = fault_code(Fault::OutsideMemory); return c.fault; }
            v = (v >> (16 * idx)) & 0xFFFFull;
        }
        c.castSet(dst, 4, v);
        if (c.fault != fault_code(Fault::None)) return c.fault;
        return fault_code(Fault::None);
    }

    // 0F 3A: pextrb 14 / pextrd 16 / pinsrb 20 / pinsrd 22 (66 required)
    static uint32_t ssePinEx3A(Ctx& c) {
        if (!c.op66) return fault_code(Fault::UnsupportedInstruction);
        const uint8_t op3 = c.f.u8();
        if (op3 != 0x14 && op3 != 0x16 && op3 != 0x20 && op3 != 0x22) return fault_code(Fault::UnsupportedInstruction);
        c.decodeRm();
        if (c.fault != fault_code(Fault::None)) return c.fault;
        const bool is64d = (op3 == 0x16 || op3 == 0x22) && c.rexW && is64;
        if (op3 == 0x14 || op3 == 0x16) { // extract: r/m <- xmm lane imm8
            const int dst = (c.mr.reg | (c.rexR << 3)) & 15;
            const int srcreg = (c.mr.reg | (c.rexR << 3)) & 15;
            const int idx = c.f.u8();
            const int laneE = (op3 == 0x14) ? 8 : 4;
            if (idx >= (laneE == 4 ? 4 : 16)) return fault_code(Fault::UnsupportedInstruction);
            uint64_t xmm[2] = { c.e.xmm[srcreg][0], c.e.xmm[srcreg][1] };
            const uint64_t bits = (laneE == 4)
                ? ((idx & 1) ? (xmm[idx >> 1] >> 32) : xmm[idx >> 1]) & 0xFFFFFFFFull
                : (static_cast<uint64_t>(idx) < 8 ? (xmm[0] >> (8 * idx)) : (xmm[1] >> (8 * (idx - 8)))) & 0xFFull;
            if (c.oIsReg()) c.castSet((c.mr.rm | (c.rexB << 3)) & 15, laneE == 4 ? (is64d ? 8 : 4) : 1, bits);
            else {
                const uint64_t ea = c.eaCalc();
                if (laneE == 4) {
                    if (is64d) {
                        if (!memSt<uint64_t>(c.e, ea, bits)) { c.fault = fault_code(Fault::OutsideMemory); return c.fault; }
                    } else if (!memSt<uint32_t>(c.e, ea, static_cast<uint32_t>(bits & maskSz(4)))) { c.fault = fault_code(Fault::OutsideMemory); return c.fault; }
                } else if (!memSt(c.e, ea, static_cast<uint8_t>(bits))) { c.fault = fault_code(Fault::OutsideMemory); return c.fault; }
            }
            if (c.fault != fault_code(Fault::None)) return c.fault;
            return fault_code(Fault::None);
        }
        // insert: xmm lane <- r8/m8 or r32/m32 (sign/zero rules: pinsrd zero-extends, pinsrb)
        const int dst = (c.mr.reg | (c.rexR << 3)) & 15;
        const int idx = c.f.u8();
        const bool dword = (op3 == 0x22);
        const int laneE = dword ? 4 : 1;
        const int laneN = dword ? 4 : 16;
        if (idx >= laneN) return fault_code(Fault::UnsupportedInstruction);
        const uint64_t v = c.oVal(laneE);
        if (c.fault != fault_code(Fault::None)) return c.fault;
        uint64_t word = 0;
        if (dword) {
            const int q = (idx >> 1) & 1;
            word = static_cast<uint64_t>(static_cast<uint32_t>(v)) << (32 * (idx & 1));
            if (q) c.e.xmm[dst][1] = (c.e.xmm[dst][1] & 0xFFFFFFFFull) | word;
            else c.e.xmm[dst][0] = (c.e.xmm[dst][0] & 0xFFFFFFFF00000000ull) | word;
        } else {
            const int lane = (idx >> 3) & 1;
            c.e.xmm[dst][lane] = (c.e.xmm[dst][lane] & ~(0xFFull << (8 * (idx & 7)))) | ((v & 0xFFull) << (8 * (idx & 7)));
        }
        return fault_code(Fault::None);
    }

    // ---- x87 (batch C) ----
    // 8 stacked doubles with TOP in e.fTop; ST(i) = x87St[(fTop + i) & 7].
    // Compares keep C0/C1/C2/C3 in fsw at their real status-word positions
    // (8/9/10/14); fnstsw/fstsw emit fsw with TOP in bits 11-13.
    static double fpuSt(Emu& e, int i) { return e.x87St[(e.fTop + (i & 7)) & 7]; }
    static void fpuStSet(Emu& e, int i, double v) { e.x87St[(e.fTop + (i & 7)) & 7] = v; }
    static void fpuPush(Emu& e, double v) { e.fTop = (e.fTop - 1) & 7; e.x87St[e.fTop] = v; }
    static void fpuPop(Emu& e) { e.fTop = (e.fTop + 1) & 7; }
    static void fpuCom(Emu& e, double a, double b, bool setFlags) {
        e.fsw &= ~0x4700u; // C0..C3
        if (a != a || b != b) e.fsw |= 0x4700u; // unordered
        else if (a < b) e.fsw |= 0x0100u;
        else if (a == b) e.fsw |= 0x4000u;
        if (setFlags) { e.zf = ((e.fsw >> 14) & 1) != 0; e.pf = ((e.fsw >> 10) & 1) != 0; e.cf = ((e.fsw >> 8) & 1) != 0; }
    }
    // FIST-style store: default control word rounds to nearest even;
    // out-of-range/NaN writes the integer indefinite value (INT_MIN).
    static int64_t fpuToInt(double v, int64_t indef) {
        if (v != v || v < (indef == 0x8000000000000000ll ? -9223372036854775808.0 : -2147483648.0)) return indef; // NaN + beyond range: indefinite
        const double r = std::llrint(v);
        if (r != r || r >= (indef == 0x8000000000000000ll ? 9223372036854775808.0 : 2147483648.0)) return indef;
        return static_cast<int64_t>(r);
    }
    static uint32_t fpuOom(Ctx& c) { c.fault = fault_code(Fault::OutsideMemory); return c.fault; }

    static uint32_t x87Op(Ctx& c, uint8_t op) {
        c.decodeRm();
        if (c.fault != fault_code(Fault::None)) return c.fault;
        Emu& e = c.e;
        const int r = c.mr.reg & 7;
        if (!c.oIsReg()) { // memory forms
            const uint64_t ea = c.eaCalc();
            switch (op) {
            case 0xD8: { // m32 float arithmetic
                uint32_t b;
                if (!memLd(c.e, ea, b)) return fpuOom(c);
                const double v = ffrom(b);
                switch (r) {
                case 0: fpuStSet(e, 0, fpuSt(e, 0) + v); break; // fadd
                case 1: fpuStSet(e, 0, fpuSt(e, 0) * v); break; // fmul
                case 2: fpuCom(e, fpuSt(e, 0), v, false); break; // fcom
                case 3: fpuCom(e, fpuSt(e, 0), v, false); fpuPop(e); break; // fcomp
                case 4: fpuStSet(e, 0, fpuSt(e, 0) - v); break; // fsub
                case 5: fpuStSet(e, 0, v - fpuSt(e, 0)); break; // fsubr
                case 6: fpuStSet(e, 0, fpuSt(e, 0) / v); break; // fdiv
                case 7: fpuStSet(e, 0, v / fpuSt(e, 0)); break; // fdivr
                }
                break;
            }
            case 0xD9: { // fld/fst/fstp m32; fldcw (load, control ignored); fnstcw m16
                if (r == 0) {
                    uint32_t b;
                    if (!memLd(c.e, ea, b)) return fpuOom(c);
                    fpuPush(e, ffrom(b));
                } else if (r == 2 || r == 3) {
                    if (!memSt(c.e, ea, static_cast<uint32_t>(fto(static_cast<float>(fpuSt(e, 0)))))) return fpuOom(c);
                    if (r == 3) fpuPop(e);
                } else if (r == 5) {
                    uint16_t b;
                    if (!memLd(c.e, ea, b)) return fpuOom(c);
                    e.fCw = b; // rounding modes not modeled; stored and echoed
                } else if (r == 7) {
                    if (!memSt(c.e, ea, e.fCw)) return fpuOom(c);
                } else return fault_code(Fault::UnsupportedInstruction);
                break;
            }
            case 0xDA: { // m32 int arithmetic: fiadd/fimul/ficom/ficomp/fisub/fisubr/fidiv/fidivr
                uint32_t b;
                if (!memLd(c.e, ea, b)) return fpuOom(c);
                const double v = static_cast<double>(static_cast<int32_t>(b));
                switch (r) {
                case 0: fpuStSet(e, 0, fpuSt(e, 0) + v); break;
                case 1: fpuStSet(e, 0, fpuSt(e, 0) * v); break;
                case 2: fpuCom(e, fpuSt(e, 0), v, false); break;
                case 3: fpuCom(e, fpuSt(e, 0), v, false); fpuPop(e); break;
                case 4: fpuStSet(e, 0, fpuSt(e, 0) - v); break;
                case 5: fpuStSet(e, 0, v - fpuSt(e, 0)); break;
                case 6: fpuStSet(e, 0, fpuSt(e, 0) / v); break;
                case 7: fpuStSet(e, 0, v / fpuSt(e, 0)); break;
                }
                break;
            }
            case 0xDB: { // fild m32 / fist m32 / fistp m32
                if (r == 0) {
                    uint32_t b;
                    if (!memLd(c.e, ea, b)) return fpuOom(c);
                    fpuPush(e, static_cast<double>(static_cast<int32_t>(b)));
                } else if (r == 2 || r == 3) {
                    if (!memSt(c.e, ea, static_cast<uint32_t>(static_cast<int32_t>(fpuToInt(fpuSt(e, 0), -2147483648ll))))) return fpuOom(c);
                    if (r == 3) fpuPop(e);
                } else return fault_code(Fault::UnsupportedInstruction);
                break;
            }
            case 0xDC: { // m64 double arithmetic
                uint64_t b;
                if (!memLd<uint64_t>(c.e, ea, b)) return fpuOom(c);
                const double v = dfrom(b);
                switch (r) {
                case 0: fpuStSet(e, 0, fpuSt(e, 0) + v); break;
                case 1: fpuStSet(e, 0, fpuSt(e, 0) * v); break;
                case 2: fpuCom(e, fpuSt(e, 0), v, false); break;
                case 3: fpuCom(e, fpuSt(e, 0), v, false); fpuPop(e); break;
                case 4: fpuStSet(e, 0, fpuSt(e, 0) - v); break;
                case 5: fpuStSet(e, 0, v - fpuSt(e, 0)); break;
                case 6: fpuStSet(e, 0, fpuSt(e, 0) / v); break;
                case 7: fpuStSet(e, 0, v / fpuSt(e, 0)); break;
                }
                break;
            }
            case 0xDD: { // fld/fst/fstp m64; fnstsw m16
                if (r == 0) {
                    uint64_t b;
                    if (!memLd<uint64_t>(c.e, ea, b)) return fpuOom(c);
                    fpuPush(e, dfrom(b));
                } else if (r == 2 || r == 3) {
                    if (!memSt<uint64_t>(c.e, ea, dto(fpuSt(e, 0)))) return fpuOom(c);
                    if (r == 3) fpuPop(e);
                } else if (r == 7) {
                    if (!memSt(c.e, ea, static_cast<uint16_t>(e.fsw | (e.fTop << 11)))) return fpuOom(c);
                } else return fault_code(Fault::UnsupportedInstruction);
                break;
            }
            case 0xDE: { // m16 int arithmetic (same set as DA)
                uint16_t b;
                if (!memLd(c.e, ea, b)) return fpuOom(c);
                const double v = static_cast<double>(static_cast<int16_t>(b));
                switch (r) {
                case 0: fpuStSet(e, 0, fpuSt(e, 0) + v); break;
                case 1: fpuStSet(e, 0, fpuSt(e, 0) * v); break;
                case 2: fpuCom(e, fpuSt(e, 0), v, false); break;
                case 3: fpuCom(e, fpuSt(e, 0), v, false); fpuPop(e); break;
                case 4: fpuStSet(e, 0, fpuSt(e, 0) - v); break;
                case 5: fpuStSet(e, 0, v - fpuSt(e, 0)); break;
                case 6: fpuStSet(e, 0, fpuSt(e, 0) / v); break;
                case 7: fpuStSet(e, 0, v / fpuSt(e, 0)); break;
                }
                break;
            }
            case 0xDF: { // fild/fist/fistp m16; fild/fistp m64
                if (r == 0) {
                    uint16_t b;
                    if (!memLd(c.e, ea, b)) return fpuOom(c);
                    fpuPush(e, static_cast<double>(static_cast<int16_t>(b)));
                } else if (r == 2 || r == 3 || r == 6) {
                    if (!memSt(c.e, ea, static_cast<uint16_t>(static_cast<int16_t>(fpuToInt(fpuSt(e, 0), -32768))))) return fpuOom(c);
                    if (r != 2) fpuPop(e);
                } else if (r == 5 || r == 7) {
                    uint64_t b;
                    if (r == 5 && !memLd<uint64_t>(c.e, ea, b)) return fpuOom(c);
                    if (r == 5) fpuPush(e, static_cast<double>(static_cast<int64_t>(b)));
                    else if (!memSt<uint64_t>(c.e, ea, static_cast<uint64_t>(static_cast<int64_t>(fpuToInt(fpuSt(e, 0), (-9223372036854775807ll - 1)))))) return fpuOom(c);
                    if (r == 7) fpuPop(e);
                } else return fault_code(Fault::UnsupportedInstruction);
                break;
            }
            }
            if (c.fault != fault_code(Fault::None)) return c.fault;
            return fault_code(Fault::None);
        }
        // mod==3 register forms: dst ST(i), src/cmpdst ST(0) unless noted
        const int i = c.mr.rm & 7;
        switch (op) {
        case 0xD8:
            switch (r) {
            case 0: fpuStSet(e, 0, fpuSt(e, 0) + fpuSt(e, i)); break; // fadd st0, st(i)
            case 1: fpuStSet(e, 0, fpuSt(e, 0) * fpuSt(e, i)); break;
            case 2: fpuCom(e, fpuSt(e, 0), fpuSt(e, i), false); break; // fcom st(i)
            case 3: fpuCom(e, fpuSt(e, 0), fpuSt(e, i), false); fpuPop(e); break; // fcomp
            case 4: fpuStSet(e, 0, fpuSt(e, 0) - fpuSt(e, i)); break;
            case 5: fpuStSet(e, 0, fpuSt(e, i) - fpuSt(e, 0)); break; // fsubr
            case 6: fpuStSet(e, 0, fpuSt(e, 0) / fpuSt(e, i)); break;
            case 7: fpuStSet(e, 0, fpuSt(e, i) / fpuSt(e, 0)); break; // fdivr
            }
            break;
        case 0xD9:
            switch (r) {
            case 0: fpuPush(e, fpuSt(e, i)); break; // fld st(i): push a copy
            case 1: { const double t = fpuSt(e, 0); fpuStSet(e, 0, fpuSt(e, i)); fpuStSet(e, i, t); break; } // fxch
            case 4: // E0 fchs / E1 fabs
                if (i == 0) fpuStSet(e, 0, -fpuSt(e, 0));
                else if (i == 1) fpuStSet(e, 0, std::fabs(fpuSt(e, 0)));
                else return fault_code(Fault::UnsupportedInstruction);
                break;
            case 5: { // E8-EF: push FP constants; EE fldz
                static const double consts[6] = { 1.0, std::log2(10.0), std::log2(2.7182818284590452354), 3.14159265358979323846, std::log10(2.0), std::log(2.0) };
                if (i < 6) fpuPush(e, consts[i]);
                else if (i == 6) fpuPush(e, 0.0); // fldz
                else return fault_code(Fault::UnsupportedInstruction);
                break;
            }
            case 6: // F0-F7: f2xm1/fyl2x/fptan/fpatan/fxtract/fprem1/fdecstp/fincstp
                switch (i) {
                case 0: fpuStSet(e, 0, std::pow(2.0, fpuSt(e, 0)) - 1.0); break;
                case 1: { fpuStSet(e, 1, fpuSt(e, 1) * std::log2(std::fabs(fpuSt(e, 0)))); fpuPop(e); break; } // fyl2x
                case 2: { const double t = std::tan(fpuSt(e, 0)); fpuStSet(e, 1, t); fpuPush(e, 1.0); break; } // fptan
                case 3: { fpuStSet(e, 1, std::atan(fpuSt(e, 1) / fpuSt(e, 0))); fpuPop(e); break; } // fpatan
                case 4: { const double v = fpuSt(e, 0); // fxtract: st0 = exponent part, push significand below
                             if (v != v || v >= 1e308 * 4 || v <= -1e308 * 4) { fpuPush(e, v); break; }
                             int exp10 = 0; const double m = std::frexp(v, &exp10); fpuPush(e, m); fpuStSet(e, 0, static_cast<double>(exp10 - 1)); break; }
                case 5: { const double y = fpuSt(e, 1), x = fpuSt(e, 0); const double q = std::nearbyint(x / y); fpuStSet(e, 0, x - y * q); break; } // fprem1
                case 6: e.fTop = (e.fTop - 1) & 7; break; // fdecstp
                case 7: e.fTop = (e.fTop + 1) & 7; break; // fincstp
                }
                break;
            case 7: // F8-FF: fprem/fyl2xp1/fsqrt/fsincos/frndint/fscale/fsin/fcos
                switch (i) {
                case 0: { const double y = fpuSt(e, 1), x = fpuSt(e, 0); const double q = std::trunc(x / y); // fprem: partial quotient in C0..C3
                             e.fsw &= ~0x4700u;
                             const int64_t qi = static_cast<int64_t>(q);
                             e.fsw |= ((qi & 1) ? 0x100u : 0) | ((qi & 2) ? 0x200u : 0) | ((qi & 4) ? 0x4000u : 0);
                             fpuStSet(e, 0, x - y * q); break; }
                case 1: { fpuStSet(e, 1, fpuSt(e, 1) * std::log2(std::fabs(fpuSt(e, 0)) + 1.0)); fpuPop(e); break; } // fyl2xp1
                case 2: fpuStSet(e, 0, std::sqrt(fpuSt(e, 0))); break; // fsqrt
                case 3: { const double v = fpuSt(e, 0); fpuPush(e, std::cos(v)); fpuStSet(e, 1, std::sin(v)); break; } // fsincos: st0=cos, st1=sin
                case 4: fpuStSet(e, 0, static_cast<double>(std::llrint(fpuSt(e, 0)))); break; // frndint (RNE)
                case 5: fpuStSet(e, 0, fpuSt(e, 0) * std::pow(2.0, std::trunc(fpuSt(e, 1)))); break; // fscale
                case 6: fpuStSet(e, 0, std::sin(fpuSt(e, 0))); break; // fsin
                case 7: fpuStSet(e, 0, std::cos(fpuSt(e, 0))); break; // fcos
                }
                break;
            }
            break;
        case 0xDA: // fcmov cc (reg 0-3 only): st0 = st(i) when condition holds
            if (r == 0 ? e.cf : r == 1 ? e.zf : r == 2 ? (e.cf || e.zf) : e.pf)
                fpuStSet(e, 0, fpuSt(e, i));
            if (r > 3) return fault_code(Fault::UnsupportedInstruction);
            break;
        case 0xDB:
            if (r == 4) { // E2 fnclex / E3 fninit
                if (i == 2) { e.fsw = 0; }
                else if (i == 3) { e.fsw = 0; e.fTop = 0; e.fCw = 0x037F; }
                else return fault_code(Fault::UnsupportedInstruction);
                break;
            }
            if (r == 3) { // fcmovnu st0, st(i)
                if (!e.pf) fpuStSet(e, 0, fpuSt(e, i));
                break;
            }
            if (r == 5 || r == 6) { // DB E8+i fucomi / DB F0+i fcomi: set EFLAGS
                fpuCom(e, fpuSt(e, 0), fpuSt(e, i), true);
                break;
            }
            return fault_code(Fault::UnsupportedInstruction);
        case 0xDC:
            switch (r) {
            case 0: fpuStSet(e, i, fpuSt(e, i) + fpuSt(e, 0)); break;
            case 1: fpuStSet(e, i, fpuSt(e, i) * fpuSt(e, 0)); break;
            // DC/DE reg-table sub/div directions differ from D8/DA (verified
            // on real hardware): /4 reverse, /5 plain, /6 reverse, /7 plain
            case 4: fpuStSet(e, i, fpuSt(e, 0) - fpuSt(e, i)); break;
            case 5: fpuStSet(e, i, fpuSt(e, i) - fpuSt(e, 0)); break;
            case 6: fpuStSet(e, i, fpuSt(e, 0) / fpuSt(e, i)); break;
            case 7: fpuStSet(e, i, fpuSt(e, i) / fpuSt(e, 0)); break;
            default: return fault_code(Fault::UnsupportedInstruction);
            }
            break;
        case 0xDD:
            switch (r) {
            case 0: break; // ffree st(i)
            case 1: { const double t = fpuSt(e, 0); fpuStSet(e, 0, fpuSt(e, i)); fpuStSet(e, i, t); break; } // fxch (DD C8+i)
            case 2: fpuStSet(e, i, fpuSt(e, 0)); break; // fst st(i)
            case 3: fpuStSet(e, i, fpuSt(e, 0)); fpuPop(e); break; // fstp st(i)
            case 4: fpuCom(e, fpuSt(e, 0), fpuSt(e, i), false); break; // fucom
            case 5: fpuCom(e, fpuSt(e, 0), fpuSt(e, i), false); fpuPop(e); break; // fucomp
            default: return fault_code(Fault::UnsupportedInstruction);
            }
            break;
        case 0xDE: // like DC but pops (rotation form); DE D9 = fcompp
            if (r == 3 && i == 1) { fpuCom(e, fpuSt(e, 0), fpuSt(e, 1), false); fpuPop(e); fpuPop(e); break; } // fcompp
            switch (r) {
            case 0: fpuStSet(e, i, fpuSt(e, i) + fpuSt(e, 0)); fpuPop(e); break; // faddp
            case 1: fpuStSet(e, i, fpuSt(e, i) * fpuSt(e, 0)); fpuPop(e); break; // fmulp
            case 2: fpuCom(e, fpuSt(e, 0), fpuSt(e, i), false); fpuPop(e); break; // fcomp st(i)
            case 4: fpuStSet(e, i, fpuSt(e, 0) - fpuSt(e, i)); fpuPop(e); break; // fsubp st(i), st0
            case 5: fpuStSet(e, i, fpuSt(e, i) - fpuSt(e, 0)); fpuPop(e); break; // fsubrp
            case 6: fpuStSet(e, i, fpuSt(e, 0) / fpuSt(e, i)); fpuPop(e); break; // fdivp
            case 7: fpuStSet(e, i, fpuSt(e, i) / fpuSt(e, 0)); fpuPop(e); break; // fdivrp
            default: return fault_code(Fault::UnsupportedInstruction);
            }
            break;
        case 0xDF: // DF E0 fnstsw ax; DF E8+i fucomip / DF F0+i fcomip: compare, set EFLAGS, pop
            if (r == 4 && i == 0) { e.r[0] = (e.r[0] & ~0xFFFFull) | static_cast<uint64_t>((e.fsw | (e.fTop << 11)) & 0xFFFF); break; } // fnstsw ax (implicit AX = reg 0)
            if (r == 5 || r == 6) { fpuCom(e, fpuSt(e, 0), fpuSt(e, i), true); fpuPop(e); break; }
            return fault_code(Fault::UnsupportedInstruction);
        }
        if (c.fault != fault_code(Fault::None)) return c.fault;
        return fault_code(Fault::None);
    }

    // ---- guest memory ----

    static bool push64(Emu& e, uint64_t v) {
        if constexpr (is64) {
            const uint64_t addr = e.r[kRSP] - 8;
            if (!memSt<uint64_t>(e, addr, v)) return false;
            e.r[kRSP] = addr;
            return true;
        } else {
            constexpr uint64_t m = 0xFFFFFFFFull;
            const uint64_t addr = e.r[kRSP] - 4;
            if (!memSt<uint32_t>(e, addr, static_cast<uint32_t>(v & m))) return false;
            e.r[kRSP] = addr;
            return true;
        }
    }
    static bool pop64(Emu& e, uint64_t& v) {
        if constexpr (is64) {
            if (!memLd<uint64_t>(e, e.r[kRSP], v)) return false;
            e.r[kRSP] += 8;
            return true;
        } else {
            uint32_t w = 0;
            if (!memLd(e, e.r[kRSP], w)) return false;
            e.r[kRSP] += 4;
            v = w;
            return true;
        }
    }

    // ---- instruction fetch / dispatch ----

    static uint32_t stepOne(Ctx& c) {
        Fetch& f = c.f;
        for (;;) {
            if (f.pos >= f.len) return fault_code(Fault::OutsideMemory); // truncated blob: fetch outside image
            const uint8_t p = f.data[f.pos];
            switch (p) {
            case 0x66: c.op66 = true; ++f.pos; continue;
            case 0x67: ++f.pos; continue;
            case 0x64:
                if constexpr (is64) { ++f.pos; } // segment prefixes are no-ops here
                else { c.segFs = 1; ++f.pos; }
                continue;
            case 0x65:
                if constexpr (is64) { c.segGs = 1; ++f.pos; }
                else { ++f.pos; }
                continue;
            case 0xF3: c.rep = true; ++f.pos; continue;
            case 0xF2: c.rep = true; c.repF2 = true; ++f.pos; continue; // repne for string ops; crc32 marker
            case 0xF0: ++f.pos; continue; // lock: single-threaded, nothing to lock
            case 0x2E: case 0x3E: case 0x26: case 0x36:
                ++f.pos; continue;
            case 0x40: case 0x41: case 0x42: case 0x43:
            case 0x44: case 0x45: case 0x46: case 0x47:
            case 0x48: case 0x49: case 0x4A: case 0x4B:
            case 0x4C: case 0x4D: case 0x4E: case 0x4F:
                if constexpr (is64) { // REX on x64; on x86 these are inc/dec (step)
                    c.rexW = (p >> 3) & 1;
                    c.rexR = (p >> 2) & 1;
                    c.rexX = (p >> 1) & 1;
                    c.rexB = p & 1;
                    c.rexUsed = true;
                    ++f.pos;
                    continue;
                }
                return step(c);
            default:
                return step(c);
            }
        }
    }

    static uint32_t step(Ctx& c) {
        Fetch& f = c.f;
        const uint8_t op = f.u8();
        const int sz = c.operSz();

        switch (op) {
        case 0x00: case 0x01: case 0x02: case 0x03:
        case 0x08: case 0x09: case 0x0A: case 0x0B:
        case 0x10: case 0x11: case 0x12: case 0x13:
        case 0x18: case 0x19: case 0x1A: case 0x1B:
        case 0x20: case 0x21: case 0x22: case 0x23:
        case 0x28: case 0x29: case 0x2A: case 0x2B:
        case 0x30: case 0x31: case 0x32: case 0x33:
        case 0x38: case 0x39: case 0x3A: case 0x3B: {
            const int fam = (op >> 3) & 7;
            const int form = op & 7;
            const int osz = (form == 0 || form == 2) ? 1 : sz;
            c.decodeRm();
            uint64_t dst, src;
            if (form & 2) { dst = c.gVal(osz); src = c.oVal(osz); }
            else { dst = c.oVal(osz); src = c.gVal(osz); }
            if (c.fault != fault_code(Fault::None)) return c.fault;
            uint64_t res = 0;
            const uint32_t r = aluOp(c, fam, dst, src, osz, res);
            if (r != fault_code(Fault::None)) return r;
            if (fam != 7) {
                if (osz == 1) { if (form & 2) c.g8Write(res); else c.o8Write(res); }
                else { if (form & 2) c.gSet(osz, res); else c.oSet(osz, res); }
            }
            if (c.fault != fault_code(Fault::None)) return c.fault;
            return fault_code(Fault::None);
        }
        case 0x04: case 0x0C: case 0x14: case 0x1C:
        case 0x24: case 0x2C: case 0x34: case 0x3C: {
            const int fam = (op >> 3) & 7;
            const uint8_t imm = f.u8();
            const uint64_t a = c.e.r[0] & 0xFF;
            uint64_t res = 0;
            const uint32_t r = aluOp(c, fam, a, imm, 1, res);
            if (r != fault_code(Fault::None)) return r;
            if (fam != 7) c.reg8Write(0, res);
            return fault_code(Fault::None);
        }
        case 0x05: case 0x0D: case 0x15: case 0x1D:
        case 0x25: case 0x2D: case 0x35: case 0x3D: {
            const int fam = (op >> 3) & 7;
            // 64-bit operand size still takes a sign-extended imm32
            const uint64_t imm = (sz == 8) ? sext(4, f.u32()) : c.imm64(sz, false);
            uint64_t res = 0;
            const uint32_t r = aluOp(c, fam, c.e.r[0], imm, sz, res);
            if (r != fault_code(Fault::None)) return r;
            if (fam != 7) c.castSet(0, sz, res);
            return fault_code(Fault::None);
        }
        case 0x06: case 0x07: case 0x0E: case 0x16: case 0x17: case 0x1E: case 0x1F:
        case 0x26: case 0x27: case 0x2E: case 0x2F: case 0x36: case 0x37: case 0x3E: case 0x3F:
            return fault_code(Fault::UnsupportedInstruction);

        case 0x50: case 0x51: case 0x52: case 0x53: case 0x54: case 0x55: case 0x56: case 0x57: {
            const int idx = (op & 7) | (c.rexB << 3);
            return push64(c.e, c.e.r[idx & 15]) ? fault_code(Fault::None) : fault_code(Fault::OutsideMemory);
        }
        case 0x58: case 0x59: case 0x5A: case 0x5B: case 0x5C: case 0x5D: case 0x5E: case 0x5F: {
            uint64_t v = 0;
            if (!pop64(c.e, v)) return fault_code(Fault::OutsideMemory);
            const int idx = (op & 7) | (c.rexB << 3);
            if (c.op66) c.e.r[idx & 15] = (c.e.r[idx & 15] & ~0xFFFFull) | (v & 0xFFFF);
            else c.e.r[idx & 15] = v;
            return fault_code(Fault::None);
        }
        case 0x60: {
            if constexpr (!is64) {
                // pusha: AX,CX,DX,BX,orig SP,BP,SI,DI
                const uint32_t sp0 = static_cast<uint32_t>(c.e.r[4]);
                const uint32_t vals[8] = { static_cast<uint32_t>(c.e.r[0]), static_cast<uint32_t>(c.e.r[1]),
                    static_cast<uint32_t>(c.e.r[2]), static_cast<uint32_t>(c.e.r[3]), sp0,
                    static_cast<uint32_t>(c.e.r[5]), static_cast<uint32_t>(c.e.r[6]), static_cast<uint32_t>(c.e.r[7]) };
                for (int i = 0; i < 8; ++i)
                    if (!memSt<uint32_t>(c.e, c.e.r[4] - 4, vals[i])) return fault_code(Fault::OutsideMemory);
                c.e.r[4] -= 32;
                return fault_code(Fault::None);
            }
            return fault_code(Fault::UnsupportedInstruction);
        }
        case 0x61: {
            if constexpr (!is64) {
                // popa: DI,SI,BP,SPIP(skip),BX,DX,CX,AX from lowest address
                for (int i = 0; i < 8; ++i) {
                    uint32_t v = 0;
                    if (!memLd<uint32_t>(c.e, c.e.r[4], v)) return fault_code(Fault::OutsideMemory);
                    c.e.r[4] += 4;
                    const int idx = 7 - i;
                    if (idx != 4) c.e.r[idx] = v;
                }
                return fault_code(Fault::None);
            }
            return fault_code(Fault::UnsupportedInstruction);
        }
        case 0x62: case 0x82:
            return fault_code(Fault::UnsupportedInstruction);
        case 0x63: {
            if constexpr (is64) { // movsxd
                c.decodeRm();
                if (c.fault != fault_code(Fault::None)) return c.fault;
                const uint64_t v = c.oVal(4);
                if (c.fault != fault_code(Fault::None)) return c.fault;
                const uint64_t sx = sext(4, v);
                if (c.rexW) c.gSet(8, sx); else c.gSet(4, sx);
                if (c.fault != fault_code(Fault::None)) return c.fault;
                return fault_code(Fault::None);
            }
            return fault_code(Fault::UnsupportedInstruction);
        }
        case 0x68: {
            if (c.op66) return fault_code(Fault::UnsupportedInstruction);
            const uint32_t imm = f.u32();
            return push64(c.e, sext(4, imm)) ? fault_code(Fault::None) : fault_code(Fault::OutsideMemory);
        }
        case 0x6A: {
            if (c.op66) return fault_code(Fault::UnsupportedInstruction);
            const uint8_t imm = f.u8();
            return push64(c.e, sext(1, imm)) ? fault_code(Fault::None) : fault_code(Fault::OutsideMemory);
        }
        case 0x69: case 0x6B: {
            c.decodeRm();
            // hoist the immediate: rip-relative EAs use f.pos at operand-read
            // time, which must be the instruction end
            const uint64_t imm = (op == 0x69) ? c.imm64(sz, false) : sext(1, f.u8());
            const uint64_t a = c.oVal(sz);
            if (c.fault != fault_code(Fault::None)) return c.fault;
            int ovf = 0;
            const int64_t prod = mulSigned(sz, a, imm, ovf);
            const uint64_t res = static_cast<uint64_t>(prod) & maskSz(sz);
            c.e.cf = c.e.of = ovf != 0;
            c.gSet(sz, res);
            if (c.fault != fault_code(Fault::None)) return c.fault;
            return fault_code(Fault::None);
        }

        case 0x70: case 0x71: case 0x72: case 0x73: case 0x74: case 0x75: case 0x76: case 0x77:
        case 0x78: case 0x79: case 0x7A: case 0x7B: case 0x7C: case 0x7D: case 0x7E: case 0x7F: {
            const int8_t rel = static_cast<int8_t>(f.u8());
            const uint64_t nxt = f.ipBase + f.pos;
            c.ipSet = true;
            c.e.ip = cond(c.e, op & 0xF) ? nxt + static_cast<uint64_t>(rel) : nxt;
            return fault_code(Fault::None);
        }

        case 0x80: {
            if (c.op66) return fault_code(Fault::UnsupportedInstruction);
            c.decodeRm();
            if (c.fault != fault_code(Fault::None)) return c.fault;
            const int fam = c.mr.reg;
            const uint8_t imm = f.u8(); // hoisted: EA needs pos past the imm
            const uint64_t a = c.o8Read();
            uint64_t res = 0;
            const uint32_t r = aluOp(c, fam, a, imm, 1, res);
            if (r != fault_code(Fault::None)) return r;
            if (fam != 7) c.o8Write(res);
            if (c.fault != fault_code(Fault::None)) return c.fault;
            return fault_code(Fault::None);
        }
        case 0x81: case 0x83: {
            c.decodeRm();
            if (c.fault != fault_code(Fault::None)) return c.fault;
            const int fam = c.mr.reg;
            const uint64_t imm = (op == 0x83) ? sext(1, f.u8()) :
                (sz == 8 ? sext(4, f.u32()) : c.imm64(sz, false));
            const uint64_t a = c.oVal(sz);
            if (c.fault != fault_code(Fault::None)) return c.fault;
            uint64_t res = 0;
            const uint32_t r = aluOp(c, fam, a, imm, sz, res);
            if (r != fault_code(Fault::None)) return r;
            if (fam != 7) c.oSet(sz, res);
            if (c.fault != fault_code(Fault::None)) return c.fault;
            return fault_code(Fault::None);
        }
        case 0x84: case 0x85: {
            c.decodeRm();
            if (c.fault != fault_code(Fault::None)) return c.fault;
            const uint64_t a = (op == 0x84) ? c.o8Read() : c.oVal(sz);
            const uint64_t b = (op == 0x84) ? c.g8Read() : c.gVal(sz);
            if (c.fault != fault_code(Fault::None)) return c.fault;
            if (op == 0x84) doLogicOp(c.e, 1, a & b); else doLogicOp(c.e, sz, a & b);
            return fault_code(Fault::None);
        }
        case 0x86: case 0x87: {
            c.decodeRm();
            if (c.fault != fault_code(Fault::None)) return c.fault;
            const int osz = (op == 0x86) ? 1 : sz;
            const uint64_t a = (osz == 1) ? c.o8Read() : c.oVal(osz);
            const uint64_t b = (osz == 1) ? c.g8Read() : c.gVal(osz);
            if (c.fault != fault_code(Fault::None)) return c.fault;
            if (osz == 1) { c.o8Write(b); c.g8Write(a); }
            else { c.oSet(osz, b); c.gSet(osz, a); }
            if (c.fault != fault_code(Fault::None)) return c.fault;
            return fault_code(Fault::None);
        }
        case 0x88: case 0x89: case 0x8A: case 0x8B: {
            c.decodeRm();
            if (c.fault != fault_code(Fault::None)) return c.fault;
            const bool rmIsSrc = (op == 0x88 || op == 0x89);
            const int osz = (op == 0x88 || op == 0x8A) ? 1 : sz;
            uint64_t v;
            if (rmIsSrc) v = (osz == 1) ? c.g8Read() : c.gVal(osz);
            else v = (osz == 1) ? c.o8Read() : c.oVal(osz);
            if (c.fault != fault_code(Fault::None)) return c.fault;
            if (rmIsSrc) { if (osz == 1) c.o8Write(v); else c.oSet(osz, v); }
            else { if (osz == 1) c.g8Write(v); else c.gSet(osz, v); }
            if (c.fault != fault_code(Fault::None)) return c.fault;
            return fault_code(Fault::None);
        }
        case 0x8C: case 0x8E: { // sreg moves: reads return a flat 0 selector, writes are no-ops
            c.decodeRm();
            if (c.fault != fault_code(Fault::None)) return c.fault;
            if (op == 0x8C) {
                if (c.oIsReg()) c.castSet(c.oRegIdx(), 2, 0);
                else { const uint64_t addr = c.eaCalc(); if (!memSt(c.e, addr, static_cast<uint16_t>(0))) c.fault = fault_code(Fault::OutsideMemory); }
            }
            if (c.fault != fault_code(Fault::None)) return c.fault;
            return fault_code(Fault::None);
        }
        case 0xD8: case 0xD9: case 0xDA: case 0xDB:
        case 0xDC: case 0xDD: case 0xDE: case 0xDF:
            return x87Op(c, op);
        case 0x9B: // fwait: no async FP state to synchronize
            return fault_code(Fault::None);
        case 0x8D: {
            c.decodeRm();
            if (c.fault != fault_code(Fault::None)) return c.fault;
            if (c.oIsReg()) return fault_code(Fault::UnsupportedInstruction);
            const uint64_t a = c.eaCalc();
            if (c.rexW) c.gSet(8, a); else if (c.op66) c.gSet(2, a & 0xFFFF); else c.gSet(4, a);
            if (c.fault != fault_code(Fault::None)) return c.fault;
            return fault_code(Fault::None);
        }
        case 0x8F: {
            uint64_t v = 0;
            if (!pop64(c.e, v)) return fault_code(Fault::OutsideMemory);
            c.decodeRm();
            if (c.fault != fault_code(Fault::None)) return c.fault;
            c.oSet(sz, v);
            if (c.fault != fault_code(Fault::None)) return c.fault;
            return fault_code(Fault::None);
        }
        case 0x90: return fault_code(Fault::None);
        case 0x91: case 0x92: case 0x93: case 0x94: case 0x95: case 0x96: case 0x97: {
            const int idx = (op & 7) | (c.rexB << 3);
            const uint64_t ra = c.e.r[0];
            c.e.r[0] = c.e.r[idx & 15];
            c.e.r[idx & 15] = ra;
            return fault_code(Fault::None);
        }
        case 0x98: { // cbw/cwde/cdqe
            if (is64) {
                if (c.rexW) { c.e.r[0] = sext(4, c.e.r[0]); }
                else c.e.r[0] = (c.e.r[0] & ~0xFFFFFFFFull) | sext(2, c.e.r[0] & 0xFFFF);
            } else if (c.op66) {
                c.e.r[0] = (c.e.r[0] & ~0xFFFFFFFFull) | sext(2, c.e.r[0] & 0xFFFF);
            } else {
                c.e.r[0] = (c.e.r[0] & ~0xFFFFull) | sext(1, c.e.r[0] & 0xFF);
            }
            return fault_code(Fault::None);
        }
        case 0x99: { // cwd/cdq/cqo
            if (is64) {
                if (c.rexW) c.e.r[2] = (c.e.r[0] & 0x8000000000000000ull) ? ~0ull : 0;
                else c.e.r[2] = (c.e.r[0] & 0x80000000ull) ? 0xFFFFFFFFull : 0;
            } else if (c.op66) {
                c.e.r[2] = (c.e.r[0] & 0x80000000ull) ? 0xFFFFFFFFull : 0;
            } else {
                c.e.r[2] = (c.e.r[0] & 0x8000ull) ? 0xFFFFull : 0;
            }
            return fault_code(Fault::None);
        }
        case 0x9C: {
            const uint64_t fl = (c.e.cf ? 1 : 0) | 2 | (c.e.pf ? 4 : 0) |
                                (c.e.af ? 0x10 : 0) | (c.e.zf ? 0x40 : 0) |
                                (c.e.sf ? 0x80 : 0) | (c.e.df ? 0x400 : 0) |
                                (c.e.of ? 0x800 : 0);
            return push64(c.e, fl) ? fault_code(Fault::None) : fault_code(Fault::OutsideMemory);
        }
        case 0x9D: {
            uint64_t fl = 0;
            if (!pop64(c.e, fl)) return fault_code(Fault::OutsideMemory);
            c.e.cf = (fl & 1) != 0;
            c.e.pf = (fl & 4) != 0;
            c.e.af = (fl & 0x10) != 0;
            c.e.zf = (fl & 0x40) != 0;
            c.e.sf = (fl & 0x80) != 0;
            c.e.df = (fl & 0x400) != 0;
            c.e.of = (fl & 0x800) != 0;
            return fault_code(Fault::None);
        }
        case 0x9F: { // lahf: ah = sf zf 0 af 0 pf 1 cf
            const uint64_t b = (c.e.sf ? 0x80 : 0) | (c.e.zf ? 0x40 : 0) |
                               (c.e.af ? 0x10 : 0) | (c.e.pf ? 4 : 0) | 2 |
                               (c.e.cf ? 1 : 0);
            c.e.r[0] = (c.e.r[0] & ~0xFF00ull) | (b << 8);
            return fault_code(Fault::None);
        }
        case 0x9E: { // sahf
            const uint64_t ah = (c.e.r[0] >> 8) & 0xFF;
            c.e.sf = (ah & 0x80) != 0;
            c.e.zf = (ah & 0x40) != 0;
            c.e.af = (ah & 0x10) != 0;
            c.e.pf = (ah & 0x04) != 0;
            c.e.cf = (ah & 0x01) != 0;
            return fault_code(Fault::None);
        }
        case 0xA0: case 0xA1: case 0xA2: case 0xA3: {
            if constexpr (is64) {
                const uint64_t addr = f.u64() + (c.segGs ? c.e.gsBase : 0);
                int osz;
                if (op == 0xA0 || op == 0xA2) osz = 1;
                else if (c.op66) osz = 2;
                else osz = c.rexW ? 8 : 4;
                if (op == 0xA0 || op == 0xA1) {
                    uint64_t v = 0;
                    if (osz == 1) { uint8_t w; if (!memLd(c.e, addr, w)) return fault_code(Fault::OutsideMemory); v = w; }
                    else if (osz == 2) { uint16_t w; if (!memLd(c.e, addr, w)) return fault_code(Fault::OutsideMemory); v = w; }
                    else if (osz == 4) { uint32_t w; if (!memLd(c.e, addr, w)) return fault_code(Fault::OutsideMemory); v = w; }
                    else { if (!memLd(c.e, addr, v)) return fault_code(Fault::OutsideMemory); }
                    if (op == 0xA0) c.reg8Write(0, v);
                    else c.e.r[0] = (c.e.r[0] & ~maskSz(osz)) | (v & maskSz(osz));
                } else {
                    const uint64_t v = (op == 0xA2) ? (c.e.r[0] & 0xFF) : (c.e.r[0] & maskSz(osz));
                    if (osz == 1) { if (!memSt(c.e, addr, static_cast<uint8_t>(v))) return fault_code(Fault::OutsideMemory); }
                    else if (osz == 2) { if (!memSt(c.e, addr, static_cast<uint16_t>(v))) return fault_code(Fault::OutsideMemory); }
                    else if (osz == 4) { if (!memSt(c.e, addr, static_cast<uint32_t>(v))) return fault_code(Fault::OutsideMemory); }
                    else { if (!memSt(c.e, addr, v)) return fault_code(Fault::OutsideMemory); }
                }
            } else {
                const uint32_t addr = f.u32() + (c.segFs ? static_cast<uint32_t>(c.e.fsBase) : 0);
                const int osz = c.op66 ? 2 : 4;
                if (op == 0xA0 || op == 0xA1) {
                    uint64_t v = 0;
                    if (osz == 2) { uint16_t w; if (!memLd(c.e, addr, w)) return fault_code(Fault::OutsideMemory); v = w; }
                    else { uint32_t w; if (!memLd(c.e, addr, w)) return fault_code(Fault::OutsideMemory); v = w; }
                    if (op == 0xA0) c.reg8Write(0, v);
                    else if (osz == 2) c.e.r[0] = (c.e.r[0] & ~0xFFFFull) | v;
                    else c.e.r[0] = v;
                } else {
                    const uint64_t v = (op == 0xA2) ? (c.e.r[0] & 0xFF) : (c.e.r[0] & maskSz(osz));
                    if (op == 0xA2) { if (!memSt(c.e, addr, static_cast<uint8_t>(v))) return fault_code(Fault::OutsideMemory); }
                    else if (osz == 2) { if (!memSt(c.e, addr, static_cast<uint16_t>(v))) return fault_code(Fault::OutsideMemory); }
                    else { if (!memSt(c.e, addr, static_cast<uint32_t>(v))) return fault_code(Fault::OutsideMemory); }
                }
            }
            return fault_code(Fault::None);
        }
        case 0xA4: case 0xA5: case 0xAA: case 0xAB: {
            if constexpr (is64) { // movs/stos: rep budget charged per iteration
                const int szCode = (op == 0xA4 || op == 0xAA) ? 1 : (c.op66 ? 2 : (c.rexW ? 8 : 4));
                const int stepv = c.e.df ? -szCode : szCode;
                const bool mov = (op == 0xA4 || op == 0xA5);
                if (c.rep && c.e.r[1] == 0) return fault_code(Fault::None);
                for (;;) {
                    if (c.e.budget == 0) return fault_code(Fault::Budget);
                    --c.e.budget;
                    const uint64_t si = c.e.r[6], di = c.e.r[7];
                    uint64_t v = c.e.r[0] & maskSz(szCode);
                    if (mov) {
                        if (szCode == 1) { uint8_t t; if (!memLd(c.e, si, t)) return fault_code(Fault::OutsideMemory); v = t; }
                        else if (szCode == 2) { uint16_t t; if (!memLd(c.e, si, t)) return fault_code(Fault::OutsideMemory); v = t; }
                        else if (szCode == 4) { uint32_t t; if (!memLd(c.e, si, t)) return fault_code(Fault::OutsideMemory); v = t; }
                        else { uint64_t t; if (!memLd(c.e, si, t)) return fault_code(Fault::OutsideMemory); v = t; }
                        c.e.r[6] = si + static_cast<uint64_t>(stepv);
                    }
                    if (szCode == 1) { if (!memSt(c.e, di, static_cast<uint8_t>(v))) return fault_code(Fault::OutsideMemory); }
                    else if (szCode == 2) { if (!memSt(c.e, di, static_cast<uint16_t>(v))) return fault_code(Fault::OutsideMemory); }
                    else if (szCode == 4) { if (!memSt(c.e, di, static_cast<uint32_t>(v))) return fault_code(Fault::OutsideMemory); }
                    else { if (!memSt(c.e, di, v)) return fault_code(Fault::OutsideMemory); }
                    c.e.r[7] = di + static_cast<uint64_t>(stepv);
                    if (!c.rep) break;
                    --c.e.r[1];
                    if (c.e.r[1] == 0) break;
                }
                return fault_code(Fault::None);
            } else { // x86: same loop, 32-bit truncated addressing
                const int szCode = (op == 0xA4 || op == 0xAA) ? 1 : (c.op66 ? 2 : 4);
                const int stepv = c.e.df ? -szCode : szCode;
                const bool mov = (op == 0xA4 || op == 0xA5);
                if (c.rep && c.e.r[1] == 0) return fault_code(Fault::None);
                for (;;) {
                    if (c.e.budget == 0) return fault_code(Fault::Budget);
                    --c.e.budget;
                    const uint64_t si = c.e.r[6] & maskSz(4), di = c.e.r[7] & maskSz(4);
                    uint64_t v = c.e.r[0] & maskSz(szCode);
                    if (mov) {
                        if (szCode == 1) { uint8_t t; if (!memLd(c.e, si, t)) return fault_code(Fault::OutsideMemory); v = t; }
                        else if (szCode == 2) { uint16_t t; if (!memLd(c.e, si, t)) return fault_code(Fault::OutsideMemory); v = t; }
                        else { uint32_t t; if (!memLd(c.e, si, t)) return fault_code(Fault::OutsideMemory); v = t; }
                        c.e.r[6] = (si + static_cast<uint64_t>(stepv)) & maskSz(4);
                    }
                    if (szCode == 1) { if (!memSt(c.e, di, static_cast<uint8_t>(v))) return fault_code(Fault::OutsideMemory); }
                    else if (szCode == 2) { if (!memSt(c.e, di, static_cast<uint16_t>(v))) return fault_code(Fault::OutsideMemory); }
                    else { if (!memSt(c.e, di, static_cast<uint32_t>(v))) return fault_code(Fault::OutsideMemory); }
                    c.e.r[7] = (di + static_cast<uint64_t>(stepv)) & maskSz(4);
                    if (!c.rep) break;
                    --c.e.r[1];
                    if (c.e.r[1] == 0) break;
                }
                return fault_code(Fault::None);
            }
        }
        case 0xAE: case 0xAF: { // scas: compare al/ax/eax/rax with [rdi], rdi steps
            if constexpr (is64) {
                const int szCode = (op == 0xAE) ? 1 : (c.op66 ? 2 : (c.rexW ? 8 : 4));
                const int stepv = c.e.df ? -szCode : szCode;
                if (c.rep && c.e.r[1] == 0) return fault_code(Fault::None);
                for (;;) {
                    if (c.e.budget == 0) return fault_code(Fault::Budget);
                    --c.e.budget;
                    const uint64_t di = c.e.r[7];
                    const uint64_t a = c.e.r[0] & maskSz(szCode);
                    uint64_t b = 0;
                    if (szCode == 1) { uint8_t t; if (!memLd(c.e, di, t)) return fault_code(Fault::OutsideMemory); b = t; }
                    else if (szCode == 2) { uint16_t t; if (!memLd(c.e, di, t)) return fault_code(Fault::OutsideMemory); b = t; }
                    else if (szCode == 4) { uint32_t t; if (!memLd(c.e, di, t)) return fault_code(Fault::OutsideMemory); b = t; }
                    else { if (!memLd(c.e, di, b)) return fault_code(Fault::OutsideMemory); }
                    doSubF(c.e, szCode, a, b);
                    c.e.r[7] = di + static_cast<uint64_t>(stepv);
                    if (!c.rep) break;
                    --c.e.r[1];
                    if (c.e.r[1] == 0 || (c.repF2 ? c.e.zf : !c.e.zf)) break;
                }
            } else {
                const int szCode = (op == 0xAE) ? 1 : (c.op66 ? 2 : 4);
                const int stepv = c.e.df ? -szCode : szCode;
                if (c.rep && c.e.r[1] == 0) return fault_code(Fault::None);
                for (;;) {
                    if (c.e.budget == 0) return fault_code(Fault::Budget);
                    --c.e.budget;
                    const uint64_t di = c.e.r[7] & 0xFFFFFFFFull;
                    const uint64_t a = c.e.r[0] & maskSz(szCode);
                    uint64_t b = 0;
                    if (szCode == 1) { uint8_t t; if (!memLd(c.e, di, t)) return fault_code(Fault::OutsideMemory); b = t; }
                    else if (szCode == 2) { uint16_t t; if (!memLd(c.e, di, t)) return fault_code(Fault::OutsideMemory); b = t; }
                    else { uint32_t t; if (!memLd(c.e, di, t)) return fault_code(Fault::OutsideMemory); b = t; }
                    doSubF(c.e, szCode, a, b);
                    c.e.r[7] = (di + static_cast<uint64_t>(stepv)) & 0xFFFFFFFFull;
                    if (!c.rep) break;
                    --c.e.r[1];
                    if (c.e.r[1] == 0 || (c.repF2 ? c.e.zf : !c.e.zf)) break;
                }
            }
            return fault_code(Fault::None);
        }
        case 0xA6: case 0xA7: {
            if constexpr (is64) {
                const int szCode = (op == 0xA6) ? 1 : (c.op66 ? 2 : (c.rexW ? 8 : 4));
                const int stepv = c.e.df ? -szCode : szCode;
                for (;;) {
                    if (c.e.budget == 0) return fault_code(Fault::Budget);
                    --c.e.budget;
                    const uint64_t si = c.e.r[6], di = c.e.r[7];
                    if (szCode == 1) { uint8_t a, b; if (!memLd(c.e, si, a) || !memLd(c.e, di, b)) return fault_code(Fault::OutsideMemory); doSubF(c.e, 1, a, b); }
                    else if (szCode == 2) { uint16_t a, b; if (!memLd(c.e, si, a) || !memLd(c.e, di, b)) return fault_code(Fault::OutsideMemory); doSubF(c.e, 2, a, b); }
                    else if (szCode == 4) { uint32_t a, b; if (!memLd(c.e, si, a) || !memLd(c.e, di, b)) return fault_code(Fault::OutsideMemory); doSubF(c.e, 4, a, b); }
                    else { uint64_t a, b; if (!memLd(c.e, si, a) || !memLd(c.e, di, b)) return fault_code(Fault::OutsideMemory); doSubF(c.e, 8, a, b); }
                    c.e.r[6] = (si + stepv) & maskSz(8);
                    c.e.r[7] = (di + stepv) & maskSz(8);
                    if (!c.rep) break;
                    --c.e.r[1];
                    if (c.e.r[1] == 0 || (c.repF2 ? c.e.zf : !c.e.zf)) break;
                }
            } else {
                const int szCode = (op == 0xA6) ? 1 : (c.op66 ? 2 : 4);
                const int stepv = c.e.df ? -szCode : szCode;
                for (;;) {
                    if (c.e.budget == 0) return fault_code(Fault::Budget);
                    --c.e.budget;
                    uint64_t si = c.e.r[6] & maskSz(4);
                    uint64_t di = c.e.r[7] & maskSz(4);
                    if (szCode == 1) { uint8_t a, b; if (!memLd(c.e, si, a) || !memLd(c.e, di, b)) return fault_code(Fault::OutsideMemory); doSubF(c.e, 1, a, b); }
                    else if (szCode == 2) { uint16_t a, b; if (!memLd(c.e, si, a) || !memLd(c.e, di, b)) return fault_code(Fault::OutsideMemory); doSubF(c.e, 2, a, b); }
                    else { uint32_t a, b; if (!memLd(c.e, si, a) || !memLd(c.e, di, b)) return fault_code(Fault::OutsideMemory); doSubF(c.e, 4, a, b); }
                    c.e.r[6] = (si + stepv) & maskSz(4);
                    c.e.r[7] = (di + stepv) & maskSz(4);
                    if (!c.rep) break;
                    --c.e.r[1];
                    if (c.e.r[1] == 0 || (c.repF2 ? c.e.zf : !c.e.zf)) break;
                }
            }
            return fault_code(Fault::None);
        }
        case 0xAC: case 0xAD: {
            const uint64_t si = c.e.r[6];
            if (op == 0xAC) {
                uint8_t v;
                if (!memLd(c.e, si, v)) { return fault_code(Fault::OutsideMemory); }
                c.reg8Write(0, v);
                c.e.r[6] = si + 1;
                return fault_code(Fault::None);
            }
            const int ls = is64 ? (c.op66 ? 2 : (c.rexW ? 8 : 4)) : (c.op66 ? 2 : 4);
            uint64_t v = 0;
            if (ls == 2) { uint16_t t; if (!memLd(c.e, si, t)) { return fault_code(Fault::OutsideMemory); } v = t; }
            else if (ls == 4) { uint32_t t; if (!memLd(c.e, si, t)) { return fault_code(Fault::OutsideMemory); } v = t; }
            else { uint64_t t; if (!memLd(c.e, si, t)) { return fault_code(Fault::OutsideMemory); } v = t; }
            if (ls == 2) c.e.r[0] = (c.e.r[0] & ~0xFFFFull) | v;
            else if (ls == 4) c.e.r[0] = v & 0xFFFFFFFFull;
            else c.e.r[0] = v;
            c.e.r[6] = si + static_cast<uint64_t>(ls);
            return fault_code(Fault::None);
        }
        case 0xA8: {
            const uint8_t imm = f.u8();
            doLogicOp(c.e, 1, (c.e.r[0] & 0xFF) & imm);
            return fault_code(Fault::None);
        }
        case 0xA9: {
            // 64-bit operand size still takes an imm32
            const uint64_t imm = (sz == 8) ? sext(4, f.u32()) : c.imm64(sz, false);
            doLogicOp(c.e, sz, c.e.r[0] & imm);
            return fault_code(Fault::None);
        }
        case 0xB0: case 0xB1: case 0xB2: case 0xB3: case 0xB4: case 0xB5: case 0xB6: case 0xB7: {
            const uint8_t imm = f.u8();
            c.reg8Write((op & 7) | (c.rexB << 3), imm);
            return fault_code(Fault::None);
        }
        case 0xB8: case 0xB9: case 0xBA: case 0xBB: case 0xBC: case 0xBD: case 0xBE: case 0xBF: {
            const uint64_t imm = c.imm64(sz, false);
            if (c.fault != fault_code(Fault::None)) return c.fault;
            c.castSet((op & 7) | (c.rexB << 3), sz, imm);
            return fault_code(Fault::None);
        }
        case 0xC0: case 0xC1: case 0xD0: case 0xD1: case 0xD2: case 0xD3: {
            c.decodeRm();
            if (c.fault != fault_code(Fault::None)) return c.fault;
            int osz;
            if (op == 0xC0) osz = 1; else if (op == 0xD0 || op == 0xD2) osz = 1; else osz = sz;
            uint64_t count = 0;
            if (op == 0xC0 || op == 0xC1) count = f.u8();
            else if (op == 0xD0 || op == 0xD1) count = 1;
            else count = c.e.r[1] & 0xFF;
            count &= (osz == 8) ? 0x3F : 0x1F;
            const uint64_t a = (osz == 1) ? c.o8Read() : c.oVal(osz);
            if (c.fault != fault_code(Fault::None)) return c.fault;
            const uint64_t m = maskSz(osz), bits = bitsSz(osz);
            const uint64_t sign = 1ull << (bits - 1);
            uint64_t res = a;
            if (count != 0) {
                const int kind = c.mr.reg;
                if (kind <= 3) {
                    // rol/ror/rcl/rcr: only cf/of change; count already masked
                    uint64_t v = a, cf = c.e.cf ? 1 : 0;
                    for (uint64_t i = 0; i < count; ++i) {
                        if (kind == 0) { // rol
                            cf = (v >> (bits - 1)) & 1; v = ((v << 1) | cf) & m;
                        } else if (kind == 1) { // ror
                            cf = v & 1; v = (v >> 1) | (cf << (bits - 1));
                        } else if (kind == 2) { // rcl
                            const uint64_t nc = (v >> (bits - 1)) & 1; v = ((v << 1) | cf) & m; cf = nc;
                        } else { // rcr
                            const uint64_t nc = v & 1; v = (v >> 1) | (cf << (bits - 1)); cf = nc;
                        }
                    }
                    res = v;
                    c.e.cf = cf != 0;
                    if (count == 1) {
                        if (kind == 0) c.e.of = ((res >> (bits - 1)) & 1) != (c.e.cf);
                        else if (kind == 1) c.e.of = (((res >> (bits - 1)) & 1) != ((res >> (bits - 2)) & 1));
                    }
                    if (osz == 1) c.o8Write(res); else c.oSet(osz, res);
                    if (c.fault != fault_code(Fault::None)) return c.fault;
                    return fault_code(Fault::None);
                }
                if (kind == 4 || kind == 6) {
                    res = (a << count) & m;
                    c.e.cf = (count >= bits) ? false : ((a >> (bits - count)) & 1) != 0;
                    c.e.of = (count == 1) ? (((res & sign) != 0) != (c.e.cf)) : false;
                } else if (kind == 5) {
                    res = a >> count;
                    c.e.cf = ((a >> (count - 1)) & 1) != 0;
                    c.e.of = (count == 1) ? ((a & sign) != 0) : false;
                } else {
                    const uint64_t sa = sext(osz, a);
                    res = (static_cast<uint64_t>(static_cast<int64_t>(sa) >> count)) & m;
                    c.e.cf = ((sa >> (count - 1)) & 1) != 0;
                    c.e.of = false;
                }
                flagsNZP(c.e, osz, res);
                if (osz == 1) c.o8Write(res); else c.oSet(osz, res);
                if (c.fault != fault_code(Fault::None)) return c.fault;
            }
            return fault_code(Fault::None);
        }
        case 0xC2: {
            const uint16_t imm = f.u16();
            uint64_t v = 0;
            if (!pop64(c.e, v)) return fault_code(Fault::OutsideMemory);
            ehRetPop(c.l, v, c.e.r[kRSP]);
            c.ipSet = true;
            c.e.ip = v;
            c.e.r[4] += imm;
            return fault_code(Fault::None);
        }
        case 0xC3: {
            uint64_t v = 0;
            if (!pop64(c.e, v)) return fault_code(Fault::OutsideMemory);
            ehRetPop(c.l, v, c.e.r[kRSP]);
            c.ipSet = true;
            c.e.ip = v;
            return fault_code(Fault::None);
        }
        case 0xC4: case 0xC5:
            return fault_code(Fault::UnsupportedInstruction);
        case 0xC6: case 0xC7: {
            c.decodeRm();
            if (c.fault != fault_code(Fault::None)) return c.fault;
            const int osz = (op == 0xC6) ? 1 : sz;
            const uint64_t imm = (osz == 1) ? f.u8() :
                (osz == 8 ? sext(4, f.u32()) : c.imm64(osz, false));
            if (c.fault != fault_code(Fault::None)) return c.fault;
            if (osz == 1) c.o8Write(imm); else c.oSet(osz, imm);
            if (c.fault != fault_code(Fault::None)) return c.fault;
            return fault_code(Fault::None);
        }
        case 0xC9: {
            c.e.r[4] = c.e.r[5];
            uint64_t v = 0;
            if (!pop64(c.e, v)) return fault_code(Fault::OutsideMemory);
            c.e.r[5] = v;
            return fault_code(Fault::None);
        }
        case 0xCC:
            return fault_code(Fault::None); // int3: no debugger to raise inside the box
        case 0xCA: case 0xCB: case 0xCD: case 0xCE: case 0xCF:
        case 0xE4: case 0xE5: case 0xE6: case 0xE7:
        case 0xEE: case 0xEF: case 0xF1:
            return fault_code(Fault::UnsupportedInstruction);
        case 0xEB: {
            const int8_t rel = static_cast<int8_t>(f.u8());
            const uint64_t nxt = f.ipBase + f.pos;
            c.ipSet = true;
            c.e.ip = nxt + static_cast<uint64_t>(rel);
            return fault_code(Fault::None);
        }
        case 0xE8: {
            const uint32_t rel = f.u32();
            const uint64_t nxt = f.ipBase + f.pos + 0;
            if (!push64(c.e, nxt)) return fault_code(Fault::OutsideMemory);
            ehLogCall(c.l, nxt, c.e.r[kRSP], c.e.r[kRBP]);
            c.ipSet = true;
            c.e.ip = nxt + static_cast<uint64_t>(static_cast<int64_t>(static_cast<int32_t>(rel)));
            return fault_code(Fault::None);
        }
        case 0xE9: {
            const uint32_t rel = f.u32();
            const uint64_t nxt = f.ipBase + f.pos;
            c.ipSet = true;
            c.e.ip = nxt + static_cast<uint64_t>(static_cast<int64_t>(static_cast<int32_t>(rel)));
            return fault_code(Fault::None);
        }
        case 0xEA: case 0xEC: case 0xED:
            return fault_code(Fault::UnsupportedInstruction);
        case 0xE0: case 0xE1: case 0xE2: case 0xE3: {
            const int8_t rel = static_cast<int8_t>(f.u8());
            const uint64_t nxt = f.ipBase + f.pos;
            uint64_t rcx = c.e.r[1];
            bool take = false;
            if (op == 0xE3) take = (rcx == 0);
            else {
                rcx = rcx - 1;
                c.e.r[1] = rcx;
                take = (op == 0xE0) ? (rcx != 0 && c.e.zf) : (op == 0xE1) ? (rcx != 0 && !c.e.zf) : (rcx != 0);
            }
            c.ipSet = true;
            c.e.ip = take ? nxt + static_cast<uint64_t>(rel) : nxt;
            return fault_code(Fault::None);
        }
        case 0xF4: return fault_code(Fault::Halt); // hlt ends the stub chain, exit = EAX (runLoop caller)
        case 0xF5: c.e.cf = !c.e.cf; return fault_code(Fault::None);
        case 0xF8: c.e.cf = false; return fault_code(Fault::None);
        case 0xF9: c.e.cf = true;  return fault_code(Fault::None);
        case 0xFA: c.e.df = false; return fault_code(Fault::None);
        case 0xFB: c.e.df = true;  return fault_code(Fault::None);
        case 0xFC: c.e.df = false; return fault_code(Fault::None);
        case 0xFD: c.e.df = true;  return fault_code(Fault::None);

        case 0xF6: {
            c.decodeRm();
            if (c.fault != fault_code(Fault::None)) return c.fault;
            const int kind = c.mr.reg;
            uint8_t tImm = 0;
            if (kind == 0 || kind == 1) tImm = f.u8(); // hoisted: EA needs pos past the imm
            const uint64_t a = c.o8Read();
            if (c.fault != fault_code(Fault::None)) return c.fault;
            switch (kind) {
            case 0: case 1: {
                doLogicOp(c.e, 1, a & tImm);
                return fault_code(Fault::None);
            }
            case 2: c.o8Write(~a & 0xFF); if (c.fault != fault_code(Fault::None)) return c.fault; return fault_code(Fault::None);
            case 3: c.o8Write(doNegOp(c.e, 1, a)); if (c.fault != fault_code(Fault::None)) return c.fault; return fault_code(Fault::None);
            case 4: {
                const uint64_t p = (c.e.r[0] & 0xFF) * (a & 0xFF);
                c.e.r[0] = (c.e.r[0] & ~0xFFFFull) | (p & 0xFFFF);
                c.e.cf = c.e.of = ((p >> 8) != 0);
                return fault_code(Fault::None);
            }
            case 5: {
                const int64_t p = static_cast<int64_t>(static_cast<int8_t>(c.e.r[0] & 0xFF)) * static_cast<int64_t>(static_cast<int8_t>(a & 0xFF));
                const uint64_t res = static_cast<uint64_t>(p) & 0xFFFF;
                c.e.r[0] = (c.e.r[0] & ~0xFFFFull) | res;
                c.e.cf = c.e.of = (p != static_cast<int64_t>(static_cast<int8_t>(res)));
                return fault_code(Fault::None);
            }
            case 6: case 7: { // 8-bit div/idiv is an x86 form; x64 has no 8-bit div here
                if constexpr (!is64) {
                    // div / idiv: dividend AX, quotient AL, remainder AH
                    const uint16_t n = static_cast<uint16_t>(c.e.r[0]);
                    const uint8_t d8 = static_cast<uint8_t>(a);
                    if (!d8) return fault_code(Fault::UnsupportedInstruction); // real CPU raises #DE
                    uint8_t q, r;
                    if (kind == 6) {
                        if (n / d8 > 0xFF) return fault_code(Fault::UnsupportedInstruction);
                        q = static_cast<uint8_t>(n / d8);
                        r = static_cast<uint8_t>(n % d8);
                    } else {
                        const int32_t qq = static_cast<int16_t>(n) / static_cast<int8_t>(d8);
                        if (qq > 127 || qq < -128) return fault_code(Fault::UnsupportedInstruction);
                        q = static_cast<uint8_t>(qq);
                        r = static_cast<uint8_t>(static_cast<int16_t>(n) % static_cast<int8_t>(d8));
                    }
                    c.e.r[0] = (c.e.r[0] & ~static_cast<uint64_t>(0xFFFF)) | (static_cast<uint64_t>(r) << 8) | q;
                    return fault_code(Fault::None);
                }
                return fault_code(Fault::UnsupportedInstruction);
            }
            default: return fault_code(Fault::UnsupportedInstruction);
            }
        }
        case 0xF7: {
            c.decodeRm();
            if (c.fault != fault_code(Fault::None)) return c.fault;
            const int kind = c.mr.reg;
            uint64_t tImm = 0;
            if (kind == 0 || kind == 1) // hoisted: EA needs pos past the imm
                tImm = (sz == 8) ? sext(4, f.u32()) : c.imm64(sz, false);
            const uint64_t a = c.oVal(sz);
            if (c.fault != fault_code(Fault::None)) return c.fault;
            switch (kind) {
            case 0: case 1: {
                doLogicOp(c.e, sz, a & tImm);
                return fault_code(Fault::None);
            }
            case 2: c.oSet(sz, ~a & maskSz(sz)); if (c.fault != fault_code(Fault::None)) return c.fault; return fault_code(Fault::None);
            case 3: c.oSet(sz, doNegOp(c.e, sz, a)); if (c.fault != fault_code(Fault::None)) return c.fault; return fault_code(Fault::None);
            case 4: {
                if (sz == 8) {
                    mul64u(c.e.r[0], a, c.e.r[2], c.e.r[0]);
                    c.e.cf = c.e.of = c.e.r[2] != 0;
                    return fault_code(Fault::None);
                }
                const uint64_t p = (c.e.r[0] & maskSz(sz)) * (a & maskSz(sz));
                c.e.r[0] = p & maskSz(sz);
                const uint64_t hi = (p >> bitsSz(sz)) & maskSz(sz);
                c.e.r[2] = hi;
                c.e.cf = c.e.of = (hi != 0);
                return fault_code(Fault::None);
            }
            case 5: {
                if (sz == 8) {
                    const bool neg = (static_cast<int64_t>(c.e.r[0]) < 0) != (static_cast<int64_t>(a) < 0);
                    const uint64_t ua = static_cast<int64_t>(c.e.r[0]) < 0 ? ~c.e.r[0] + 1 : c.e.r[0];
                    const uint64_t ub = static_cast<int64_t>(a) < 0 ? ~a + 1 : a;
                    uint64_t hi, lo;
                    mul64u(ua, ub, hi, lo);
                    if (neg) neg128(hi, lo);
                    c.e.r[0] = lo;
                    c.e.r[2] = hi;
                    c.e.cf = c.e.of = (hi != static_cast<uint64_t>(static_cast<int64_t>(lo) >> 63));
                    return fault_code(Fault::None);
                }
                int ovf = 0;
                const int64_t p = mulSigned(sz, c.e.r[0], a, ovf);
                (void)ovf;
                const uint64_t res = static_cast<uint64_t>(p) & maskSz(sz);
                c.e.r[0] = res;
                c.e.r[2] = (static_cast<uint64_t>(p) >> bitsSz(sz)) & maskSz(sz);
                c.e.cf = c.e.of = (static_cast<uint64_t>(p) != sext(sz, res));
                return fault_code(Fault::None);
            }
            case 6: case 7: { // div / idiv
                const bool unsignedDiv = (kind == 6);
                if (sz == 8) {
                    if constexpr (is64) {
                        if (!a) return fault_code(Fault::UnsupportedInstruction);
                        uint64_t rem;
                        if (unsignedDiv) {
                            if (c.e.r[2] >= a) return fault_code(Fault::UnsupportedInstruction); // real CPU raises #DE here
                            c.e.r[0] = div128u(c.e.r[2], c.e.r[0], a, rem);
                        } else {
                            uint64_t hi = c.e.r[2], lo = c.e.r[0], dd = a;
                            const bool n1 = (hi >> 63) != 0;
                            const bool n2 = static_cast<int64_t>(dd) < 0;
                            if (n1) neg128(hi, lo);
                            if (n2) { uint64_t zh = 0; neg128(zh, dd); }
                            if (hi >= dd) return fault_code(Fault::UnsupportedInstruction); // quotient magnitude >= 2^64: always overflow
                            const uint64_t q = div128u(hi, lo, dd, rem);
                            if ((n1 != n2) ? (q > 0x8000000000000000ull) : (q > 0x7FFFFFFFFFFFFFFFull)) return fault_code(Fault::UnsupportedInstruction); // signed #DE
                            c.e.r[0] = (n1 != n2) ? (~q + 1) : q;
                            if (n1) rem = ~rem + 1;
                        }
                        c.e.r[2] = rem;
                        return fault_code(Fault::None);
                    }
                    return fault_code(Fault::UnsupportedInstruction);
                }
                if constexpr (!is64) {
                    if (sz == 2) {
                        const uint16_t div = static_cast<uint16_t>(a);
                        if (!div) return fault_code(Fault::UnsupportedInstruction);
                        const uint32_t n = (static_cast<uint32_t>(c.e.r[2] & 0xFFFF) << 16) |
                                           static_cast<uint32_t>(c.e.r[0] & 0xFFFF);
                        uint32_t q, r;
                        if (unsignedDiv) {
                            if (n / div > 0xFFFF) return fault_code(Fault::UnsupportedInstruction);
                            q = n / div;
                            r = n % div;
                        } else {
                            const int32_t sn = static_cast<int32_t>(n);
                            const int16_t sd = static_cast<int16_t>(div);
                            if (sd == -1 && sn == (-2147483647 - 1)) return fault_code(Fault::UnsupportedInstruction);
                            const int32_t qq = sn / sd;
                            if (qq > 32767 || qq < -32768) return fault_code(Fault::UnsupportedInstruction);
                            q = static_cast<uint32_t>(qq);
                            r = static_cast<uint32_t>(sn % sd);
                        }
                        c.e.r[0] = (c.e.r[0] & ~static_cast<uint64_t>(0xFFFF)) | (q & 0xFFFF);
                        c.e.r[2] = (c.e.r[2] & ~static_cast<uint64_t>(0xFFFF)) | (r & 0xFFFF);
                        return fault_code(Fault::None);
                    }
                    const uint32_t div = static_cast<uint32_t>(a);
                    if (!div) return fault_code(Fault::UnsupportedInstruction);
                    const uint64_t n = (static_cast<uint64_t>(c.e.r[2] & 0xFFFFFFFF) << 32) |
                                       (c.e.r[0] & 0xFFFFFFFF);
                    if (unsignedDiv) {
                        if ((n >> 32) >= div) return fault_code(Fault::UnsupportedInstruction);
                        c.e.r[0] = static_cast<uint32_t>(n / div);
                        c.e.r[2] = static_cast<uint32_t>(n % div);
                    } else {
                        const int64_t sn = static_cast<int64_t>(n);
                        const int32_t sd = static_cast<int32_t>(div);
                        if (sd == -1 && sn == (-9223372036854775807 - 1)) return fault_code(Fault::UnsupportedInstruction);
                        const int64_t qq = sn / sd;
                        if (qq > 2147483647ll || qq < -2147483648ll) return fault_code(Fault::UnsupportedInstruction);
                        c.e.r[0] = static_cast<uint32_t>(qq);
                        c.e.r[2] = static_cast<uint32_t>(sn % sd);
                    }
                    return fault_code(Fault::None);
                } else {
                    const uint32_t d = static_cast<uint32_t>(a & 0xFFFFFFFFull);
                    if (!d) return fault_code(Fault::UnsupportedInstruction);
                    const uint32_t lo = static_cast<uint32_t>(c.e.r[0]);
                    const uint32_t hi = static_cast<uint32_t>(c.e.r[2]);
                    if (unsignedDiv) {
                        const uint64_t n = (static_cast<uint64_t>(hi) << 32) | lo;
                        c.e.r[0] = static_cast<uint32_t>(n / d);
                        c.e.r[2] = static_cast<uint32_t>(n % d);
                    } else {
                        const int64_t n = (static_cast<int64_t>(static_cast<int32_t>(hi)) << 32) |
                                          static_cast<uint32_t>(lo);
                        const int32_t ds = static_cast<int32_t>(d);
                        c.e.r[0] = static_cast<uint32_t>(static_cast<int32_t>(n / ds));
                        c.e.r[2] = static_cast<uint32_t>(static_cast<int32_t>(n % ds));
                    }
                    return fault_code(Fault::None);
                }
            }
            default: return fault_code(Fault::UnsupportedInstruction);
            }
        }
        case 0xFE: {
            c.decodeRm();
            if (c.fault != fault_code(Fault::None)) return c.fault;
            const int kind = c.mr.reg;
            const uint64_t a = c.o8Read();
            if (c.fault != fault_code(Fault::None)) return c.fault;
            if (kind == 0) c.o8Write(doIncOp(c.e, 1, a));
            else if (kind == 1) c.o8Write(doDecOp(c.e, 1, a));
            else return fault_code(Fault::UnsupportedInstruction);
            if (c.fault != fault_code(Fault::None)) return c.fault;
            return fault_code(Fault::None);
        }
        case 0xFF: {
            c.decodeRm();
            if (c.fault != fault_code(Fault::None)) return c.fault;
            const int kind = c.mr.reg;
            if (kind == 0 || kind == 1) {
                const int osz = is64 ? (c.op66 ? 2 : (c.rexW ? 8 : 4)) : (c.op66 ? 2 : 4);
                const uint64_t a = c.oVal(osz);
                if (c.fault != fault_code(Fault::None)) return c.fault;
                if (kind == 0) c.oSet(osz, doIncOp(c.e, osz, a)); else c.oSet(osz, doDecOp(c.e, osz, a));
                if (c.fault != fault_code(Fault::None)) return c.fault;
                return fault_code(Fault::None);
            }
            if (kind == 2 || kind == 4) {
                if constexpr (is64) {
                    // 16-bit near call/jmp: destination is the zero-extended r/m16
                    const uint64_t a = c.oVal(c.op66 ? 2 : 8);
                    if (c.fault != fault_code(Fault::None)) return c.fault;
                    const uint64_t nxt = f.ipBase + f.pos;
                    if (kind == 2) {
                        if (!push64(c.e, nxt)) return fault_code(Fault::OutsideMemory);
                        ehLogCall(c.l, nxt, c.e.r[kRSP], c.e.r[kRBP]);
                    }
                    c.ipSet = true;
                    c.e.ip = a;
                    return fault_code(Fault::None);
                } else {
                    const uint64_t a = c.oVal(c.op66 ? 2 : 4);
                    if (c.fault != fault_code(Fault::None)) return c.fault;
                    const uint64_t nxt = f.ipBase + f.pos;
                    if (kind == 2) {
                        if (!push64(c.e, nxt)) return fault_code(Fault::OutsideMemory);
                        ehLogCall(c.l, nxt, c.e.r[kRSP], c.e.r[kRBP]);
                    }
                    c.ipSet = true;
                    c.e.ip = a;
                    return fault_code(Fault::None);
                }
            }
            if (kind == 6) {
                if constexpr (is64) {
                    const uint64_t a = c.oVal(c.op66 ? 2 : 8);
                    if (c.fault != fault_code(Fault::None)) return c.fault;
                    return push64(c.e, a) ? fault_code(Fault::None) : fault_code(Fault::OutsideMemory);
                } else {
                    const uint64_t a = c.oVal(c.op66 ? 2 : 4);
                    if (c.fault != fault_code(Fault::None)) return c.fault;
                    return push64(c.e, a) ? fault_code(Fault::None) : fault_code(Fault::OutsideMemory);
                }
            }
            return fault_code(Fault::UnsupportedInstruction);
        }
        case 0x40: case 0x41: case 0x42: case 0x43: case 0x44: case 0x45: case 0x46: case 0x47:
        case 0x48: case 0x49: case 0x4A: case 0x4B: case 0x4C: case 0x4D: case 0x4E: case 0x4F: {
            // x86 inc/dec (x64 never reaches this: stepOne consumes REX)
            if constexpr (!is64) {
                const int osz = c.op66 ? 2 : 4;
                const int idx = op & 7;
                c.e.r[idx & 15] = ((op & 8) ? doDecOp : doIncOp)(c.e, osz, c.e.r[idx & 15]);
                return fault_code(Fault::None);
            }
            return fault_code(Fault::UnsupportedInstruction);
        }

        case 0x0F: {
            const uint8_t op2 = f.u8();
            switch (op2) {
            case 0x1F: case 0x1E: {
                c.decodeRm();
                if (c.fault != fault_code(Fault::None)) return c.fault;
                return fault_code(Fault::None);
            }
            case 0x10: case 0x11: case 0x28: case 0x29: case 0x6F: case 0x7F: {
                // packed (movups/movaps/movdqa/movdqu) and scalar (F3 movss /
                // F2 movsd) data movement; NP 6F/7F is the MMX movq form
                const bool store = (op2 == 0x11 || op2 == 0x29 || op2 == 0x7F);
                const bool scalar = (op2 == 0x10 || op2 == 0x11) && (c.rep || c.repF2);
                const bool mmxQ = !c.rep && !c.repF2 && !c.op66 && (op2 == 0x6F || op2 == 0x7F);
                const bool sss = scalar && c.rep && !c.repF2; // true movss; F2 (movsd) carries repF2
                const int width = sss ? 4 : scalar ? 8 : mmxQ ? 8 : 16;
                if (!scalar && op2 == 0x28 && (c.rep || c.repF2 || c.op66)) return fault_code(Fault::UnsupportedInstruction); // movaps is NP-only here (66/F3/F2 28 is not legacy SSE2)
                c.decodeRm();
                if (c.fault != fault_code(Fault::None)) return c.fault;
                if (!store) {
                    const int dst = c.gRegIdx() & 15;
                    uint64_t v[2] = { 0, 0 };
                    if (c.oIsReg()) {
                        const int s = (c.mr.rm | (c.rexB << 3)) & 15;
                        v[0] = c.e.xmm[s][0];
                        v[1] = c.e.xmm[s][1];
                    } else {
                        const uint64_t ea = c.eaCalc();
                        if (width == 16) {
                            if (!memLd<uint64_t>(c.e, ea, v[0]) || !memLd<uint64_t>(c.e, ea + 8, v[1])) { c.fault = fault_code(Fault::OutsideMemory); return c.fault; }
                        } else if (!memLd<uint64_t>(c.e, ea, v[0])) { c.fault = fault_code(Fault::OutsideMemory); return c.fault; }
                    }
                    if (width == 16) {
                        c.e.xmm[dst][0] = v[0];
                        c.e.xmm[dst][1] = v[1];
                    } else if (scalar && !c.repF2) { // movss: only the low doubleword moves
                        c.e.xmm[dst][0] = (c.e.xmm[dst][0] & ~0xFFFFFFFFull) | (v[0] & 0xFFFFFFFFull);
                    } else if (scalar) { // movsd: the low quadword moves, upper stays
                        c.e.xmm[dst][0] = v[0];
                    } else { // movq forms: low quadword in, upper cleared
                        c.e.xmm[dst][0] = v[0];
                        c.e.xmm[dst][1] = 0;
                    }
                    return fault_code(Fault::None);
                }
                // store
                const int src = c.gRegIdx() & 15;
                if (c.oIsReg()) { // reg,reg: copies the same overlap as the load form
                    const int dstr = (c.mr.rm | (c.rexB << 3)) & 15;
                    if (width == 16) {
                        c.e.xmm[dstr][0] = c.e.xmm[src][0];
                        c.e.xmm[dstr][1] = c.e.xmm[src][1];
                    } else if (scalar && !c.repF2) { // movss reg,reg: low doubleword only
                        c.e.xmm[dstr][0] = (c.e.xmm[dstr][0] & ~0xFFFFFFFFull) | (c.e.xmm[src][0] & 0xFFFFFFFFull);
                    } else if (scalar) { // movsd reg,reg: low quadword only
                        c.e.xmm[dstr][0] = c.e.xmm[src][0];
                    } else { // movq reg,reg: low qword copied, upper cleared
                        c.e.xmm[dstr][0] = c.e.xmm[src][0];
                        c.e.xmm[dstr][1] = 0;
                    }
                    return fault_code(Fault::None);
                }
                const uint64_t ea = c.eaCalc();
                if (width == 16) {
                    if (!memSt<uint64_t>(c.e, ea, c.e.xmm[src][0]) || !memSt<uint64_t>(c.e, ea + 8, c.e.xmm[src][1])) { c.fault = fault_code(Fault::OutsideMemory); return c.fault; }
                } else if (width == 8) {
                    if (!memSt<uint64_t>(c.e, ea, c.e.xmm[src][0])) { c.fault = fault_code(Fault::OutsideMemory); return c.fault; }
                } else {
                    if (!memSt(c.e, ea, static_cast<uint32_t>(c.e.xmm[src][0]))) { c.fault = fault_code(Fault::OutsideMemory); return c.fault; }
                }
                return fault_code(Fault::None);
            }
            case 0x12: case 0x13: case 0x16: case 0x17: { // movlps/movlpd/movhps/movhpd
                // reg-reg 12/16 = movhlps/movlhps; mem 13/17 = stores of low/high
                c.decodeRm();
                if (c.fault != fault_code(Fault::None)) return c.fault;
                if (c.oIsReg()) {
                    if (op2 == 0x13 || op2 == 0x17) return fault_code(Fault::UnsupportedInstruction);
                    const int dst = c.gRegIdx() & 15;
                    const int s = (c.mr.rm | (c.rexB << 3)) & 15;
                    if (op2 == 0x12) c.e.xmm[dst][0] = c.e.xmm[s][1]; // movhlps
                    else c.e.xmm[dst][1] = c.e.xmm[s][0];             // movlhps
                    return fault_code(Fault::None);
                }
                if (op2 == 0x13 || op2 == 0x17) { // store: dst is the xmm source
                    const int src = c.gRegIdx() & 15;
                    const uint64_t ea = c.eaCalc();
                    const uint64_t v = (op2 == 0x13) ? c.e.xmm[src][0] : c.e.xmm[src][1];
                    if (!memSt<uint64_t>(c.e, ea, v)) { c.fault = fault_code(Fault::OutsideMemory); return c.fault; }
                    return fault_code(Fault::None);
                }
                const int dst = c.gRegIdx() & 15;
                const uint64_t ea = c.eaCalc();
                uint64_t v = 0;
                if (!memLd<uint64_t>(c.e, ea, v)) { c.fault = fault_code(Fault::OutsideMemory); return c.fault; }
                if (op2 == 0x12) c.e.xmm[dst][0] = v; else c.e.xmm[dst][1] = v;
                return fault_code(Fault::None);
            }
            case 0x5A: case 0x5B: case 0xE6:
                return sseCvtFlt(c, op2);
            case 0x2A: case 0x2C: case 0x2D:
                return sseCvtInt(c, op2);
            case 0x51: case 0x52: case 0x53: case 0x54: case 0x55: case 0x56: case 0x57: case 0x58:
            case 0x59: case 0x5C: case 0x5D: case 0x5E: case 0x5F:
                return sseBin(c, op2);
            case 0x14: case 0x15:
                return sseUnpck(c, op2);
            case 0xC2:
                return sseCmp(c);
            case 0xC6:
                return sseShuf(c);
            case 0x70:
                return ssePshuf(c);
            case 0x71: case 0x72: case 0x73:
                return ssePShift(c, op2);
            case 0x6E: case 0x7E: case 0xD6:
                return sseMoveDQ(c, op2);
            case 0xC4: case 0xC5:
                return ssePinEx(c, op2);
            case 0xFC: case 0xFD: case 0xFE: case 0xD4:
            case 0xF8: case 0xF9: case 0xFA: case 0xFB:
                return ssePaddSub(c, op2);
            case 0x3A: // three-byte escape 0F 3A: pinsrb/pextrb/pinsrd/pextrd forms only
                return ssePinEx3A(c);
            case 0x77: { // emms: no state to reset in this design
                return fault_code(Fault::None);
            }
            case 0xEF: { // pxor: full-width xor, both archs
                c.decodeRm();
                if (c.fault != fault_code(Fault::None)) return c.fault;
                const int dst = c.gRegIdx() & 15;
                if (c.oIsReg()) {
                    const int s = (c.mr.rm | (c.rexB << 3)) & 15;
                    c.e.xmm[dst][0] ^= c.e.xmm[s][0];
                    c.e.xmm[dst][1] ^= c.e.xmm[s][1];
                } else {
                    uint64_t src[2];
                    if (!sseSrc(c, src, 2)) { c.fault = fault_code(Fault::OutsideMemory); return c.fault; }
                    c.e.xmm[dst][0] ^= src[0];
                    c.e.xmm[dst][1] ^= src[1];
                }
                return fault_code(Fault::None);
            }
            case 0x0B: return fault_code(Fault::UnsupportedInstruction);
            case 0xA2: { // CPUID: Intel vendor; leaves past 1 report no features so
                         // the CRT runtime dispatch settles on plain SSE2
                const uint64_t leaf = c.e.r[2] & (is64 ? ~0ull : 0xFFFFFFFFull);
                if (leaf == 0)
                    c.e.r[0] = 1, c.e.r[3] = 0x756E6547,
                    c.e.r[1] = 0x49656E69, c.e.r[2] = 0x6C65746E;
                else if (leaf == 1)
                    c.e.r[0] = 0x633, c.e.r[3] = 1u << 26, c.e.r[2] = 0, c.e.r[1] = 0;
                else
                    c.e.r[0] = c.e.r[1] = c.e.r[2] = c.e.r[3] = 0;
                return fault_code(Fault::None);
            }
            case 0x05: { // syscall (x64 only): eax = NT syscall number -> native ntdll Nt*
                if constexpr (is64) {
                    void* fn = syscallFnFor(c.l, static_cast<uint32_t>(c.e.r[0]));
                    if (!fn) return fault_code(Fault::UnsupportedInstruction);
                    uint64_t args[16] = { c.e.r[1], c.e.r[2], c.e.r[8], c.e.r[9], 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
                    for (int i = 4; i < 16; ++i) {
                        uint64_t v;
                        if (memLd<uint64_t>(c.e, c.e.r[kRSP] + 0x28 + 8 * (i - 4), v)) args[i] = v;
                    }
                    uint64_t out = 0;
                    if (!callNativeWin64(reinterpret_cast<uint64_t>(fn), args, out))
                        return fault_code(Fault::NativeFault);
                    c.e.r[0] = out;
                    return fault_code(Fault::None);
                }
                return fault_code(Fault::UnsupportedInstruction); // x86: 0F 05 invalid
            }
            case 0x34: case 0x35:
                return fault_code(Fault::UnsupportedInstruction);
            case 0x40: case 0x41: case 0x42: case 0x43: case 0x44: case 0x45: case 0x46: case 0x47:
            case 0x48: case 0x49: case 0x4A: case 0x4B: case 0x4C: case 0x4D: case 0x4E: case 0x4F: {
                c.decodeRm();
                if (c.fault != fault_code(Fault::None)) return c.fault;
                if (cond(c.e, op2)) {
                    const uint64_t v = c.oVal(sz);
                    if (c.fault != fault_code(Fault::None)) return c.fault;
                    c.gSet(sz, v);
                    if (c.fault != fault_code(Fault::None)) return c.fault;
                }
                return fault_code(Fault::None);
            }
            case 0x80: case 0x81: case 0x82: case 0x83: case 0x84: case 0x85: case 0x86: case 0x87:
            case 0x88: case 0x89: case 0x8A: case 0x8B: case 0x8C: case 0x8D: case 0x8E: case 0x8F: {
                const uint32_t rel = f.u32();
                const uint64_t nxt = f.ipBase + f.pos;
                c.ipSet = true;
                c.e.ip = cond(c.e, op2 & 0xF)
                    ? nxt + static_cast<uint64_t>(static_cast<int64_t>(static_cast<int32_t>(rel)))
                    : nxt;
                return fault_code(Fault::None);
            }
            case 0x90: case 0x91: case 0x92: case 0x93: case 0x94: case 0x95: case 0x96: case 0x97:
            case 0x98: case 0x99: case 0x9A: case 0x9B: case 0x9C: case 0x9D: case 0x9E: case 0x9F: {
                c.decodeRm();
                if (c.fault != fault_code(Fault::None)) return c.fault;
                const uint64_t v = cond(c.e, op2 & 0xF) ? 1 : 0;
                if (c.oIsReg()) { const int idx = (c.mr.rm | (c.rexB << 3)) & 15; c.reg8Write(idx, v); }
                else { const uint64_t addr = c.eaCalc(); if (!memSt(c.e, addr, static_cast<uint8_t>(v))) c.fault = fault_code(Fault::OutsideMemory); }
                if (c.fault != fault_code(Fault::None)) return c.fault;
                return fault_code(Fault::None);
            }
            case 0xA3: case 0xAB: case 0xB3: case 0xBB:
            case 0xBA: { // bt/bts/btr/btc r/m, r or imm8 (x64 group)
                if constexpr (is64) {
                    c.decodeRm();
                    if (c.fault != fault_code(Fault::None)) return c.fault;
                    int kind;
                    if (op2 == 0xBA) {
                        const int r = c.mr.reg & 7;
                        if (r < 4) return fault_code(Fault::UnsupportedInstruction);
                        kind = r - 4;
                    } else kind = (op2 == 0xA3) ? 0 : (op2 == 0xAB) ? 1 : (op2 == 0xB3) ? 2 : 3;
                    const uint64_t bitImm = (op2 == 0xBA) ? f.u8() : 0; // hoisted: EA needs pos past the imm
                    const uint64_t base = c.oVal(sz);
                    if (c.fault != fault_code(Fault::None)) return c.fault;
                    const uint64_t bit = (op2 == 0xBA ? bitImm : c.gVal(sz)) % (static_cast<uint64_t>(sz) * 8);
                    const uint64_t mask = 1ull << bit;
                    c.e.cf = (base & mask) != 0;
                    if (kind == 1) c.oSet(sz, base | mask);
                    else if (kind == 2) c.oSet(sz, base & ~mask);
                    else if (kind == 3) c.oSet(sz, base ^ mask);
                    if (c.fault != fault_code(Fault::None)) return c.fault;
                    return fault_code(Fault::None);
                }
                return fault_code(Fault::UnsupportedInstruction);
            }
            case 0xB0: case 0xB1: { // cmpxchg r/m, r: single-threaded, lock is a no-op
                const int osz = (op2 == 0xB1) ? (is64 ? sz : (c.op66 ? 2 : 4)) : 1;
                c.decodeRm();
                if (c.fault != fault_code(Fault::None)) return c.fault;
                const uint64_t dst = c.oVal(osz);
                if (c.fault != fault_code(Fault::None)) return c.fault;
                const uint64_t src = c.gVal(osz);
                const uint64_t acc = c.e.r[0] & maskSz(osz);
                // flags match the real CPU: ZF means the exchange happened
                c.e.zf = dst == acc;
                if (dst == acc) {
                    c.oSet(osz, src);
                } else {
                    // reload dst: oVal/gVal may have consumed it via a register alias
                    c.e.r[0] = (c.e.r[0] & ~maskSz(osz)) | dst;
                }
                if (c.fault != fault_code(Fault::None)) return c.fault;
                return fault_code(Fault::None);
            }
            case 0xAF: {
                c.decodeRm();
                if (c.fault != fault_code(Fault::None)) return c.fault;
                const uint64_t a = c.oVal(sz);
                if (c.fault != fault_code(Fault::None)) return c.fault;
                int ovf = 0;
                const int64_t prod = mulSigned(sz, c.gVal(sz), a, ovf);
                const uint64_t res = static_cast<uint64_t>(prod) & maskSz(sz);
                c.e.cf = c.e.of = ovf != 0;
                c.gSet(sz, res);
                if (c.fault != fault_code(Fault::None)) return c.fault;
                return fault_code(Fault::None);
            }
            case 0xA4: case 0xA5: case 0xAC: case 0xAD: { // shld/shrd r/m, r, imm8|cl
                c.decodeRm();
                if (c.fault != fault_code(Fault::None)) return c.fault;
                const uint64_t src = c.gVal(sz);
                // hoisted: rip-relative EA needs pos past the imm
                uint64_t count = (op2 == 0xA4 || op2 == 0xAC) ? f.u8() : c.e.r[1] & 0xFF;
                const uint64_t dst0 = c.oVal(sz);
                if (c.fault != fault_code(Fault::None)) return c.fault;
                count &= (sz == 8) ? 0x3F : 0x1F;
                if (count != 0) {
                    const uint64_t m = maskSz(sz), bits = bitsSz(sz);
                    const bool left = (op2 == 0xA4 || op2 == 0xA5);
                    if (count > bits) count = bits; // count > width is undefined; src fills dst
                    uint64_t res;
                    if (left) {
                        res = ((dst0 << count) | (src >> (bits - count))) & m;
                        c.e.cf = (src >> (bits - count)) & 1;
                    } else {
                        res = ((dst0 >> count) | (src << (bits - count))) & m;
                        c.e.cf = (dst0 >> (count - 1)) & 1;
                    }
                    c.e.of = (count == 1) ? (((res ^ dst0) >> (bits - 1)) & 1) != 0 : false;
                    flagsNZP(c.e, sz, res);
                    c.oSet(sz, res);
                    if (c.fault != fault_code(Fault::None)) return c.fault;
                }
                return fault_code(Fault::None);
            }
            case 0xB8: { // F3 0F B8 = popcnt; otherwise not supported
                if (!c.rep || c.repF2) return fault_code(Fault::UnsupportedInstruction);
                c.decodeRm();
                if (c.fault != fault_code(Fault::None)) return c.fault;
                uint64_t s = c.oVal(sz);
                if (c.fault != fault_code(Fault::None)) return c.fault;
                uint64_t p = 0;
                while (s) { p += s & 1; s >>= 1; }
                flagsNZP(c.e, sz, p);
                c.gSet(sz, p);
                if (c.fault != fault_code(Fault::None)) return c.fault;
                return fault_code(Fault::None);
            }
            case 0x38: { // three-byte escape: F2 0F 38 F0/F1 = crc32
                const uint8_t op3 = f.u8();
                if (op3 != 0xF0 && op3 != 0xF1) return fault_code(Fault::UnsupportedInstruction);
                if (!c.repF2) return fault_code(Fault::UnsupportedInstruction);
                c.decodeRm();
                if (c.fault != fault_code(Fault::None)) return c.fault;
                const int osz = (op3 == 0xF0) ? 1 : (c.rexW && is64) ? 8 : (c.op66 ? 2 : 4);
                const int nbytes = osz;
                const uint64_t s = c.oVal(osz);
                if (c.fault != fault_code(Fault::None)) return c.fault;
                constexpr uint32_t kCrcPoly = 0x82F63B78u; // reversed Castagnoli
                uint32_t crc = ~static_cast<uint32_t>(c.e.r[0]);
                for (int i = 0; i < nbytes; ++i) {
                    crc ^= static_cast<uint32_t>((s >> (8 * i)) & 0xFF);
                    for (int b = 0; b < 8; ++b)
                        crc = (crc >> 1) ^ (kCrcPoly & (0u - (crc & 1)));
                }
                crc = ~crc;
                const int dsz = (c.rexW && is64) ? 8 : 4;
                c.gSet(dsz, crc);
                if (c.fault != fault_code(Fault::None)) return c.fault;
                return fault_code(Fault::None);
            }
            case 0xBC: case 0xBD: { // bsf/bsr
                c.decodeRm();
                if (c.fault != fault_code(Fault::None)) return c.fault;
                const uint64_t s = c.oVal(sz);
                if (c.fault != fault_code(Fault::None)) return c.fault;
                c.e.zf = s == 0;
                if (s != 0) {
                    uint64_t idx = 0;
                    if (op2 == 0xBC) { while (((s >> idx) & 1) == 0) ++idx; }
                    else { idx = bitsSz(sz) - 1; while (((s >> idx) & 1) == 0) --idx; }
                    c.gSet(sz, idx);
                    if (c.fault != fault_code(Fault::None)) return c.fault;
                }
                return fault_code(Fault::None);
            }
            case 0xC0: case 0xC1: { // xadd
                const int osz = (op2 == 0xC0) ? 1 : sz;
                c.decodeRm();
                if (c.fault != fault_code(Fault::None)) return c.fault;
                const uint64_t a = (osz == 1) ? c.o8Read() : c.oVal(osz);
                const uint64_t b = (osz == 1) ? c.g8Read() : c.gVal(osz);
                if (c.fault != fault_code(Fault::None)) return c.fault;
                uint64_t sum = 0;
                aluOp(c, 0, a, b, osz, sum);
                if (osz == 1) { c.g8Write(a); c.o8Write(sum); }
                else { c.gSet(osz, a); c.oSet(osz, sum); }
                if (c.fault != fault_code(Fault::None)) return c.fault;
                return fault_code(Fault::None);
            }
            case 0xA0: case 0xA1: case 0xA8: case 0xA9: { // push/pop fs/gs: flat zero selector
                (void)c.op66;
                if (op2 == 0xA0 || op2 == 0xA8)
                    return push64(c.e, 0) ? fault_code(Fault::None) : fault_code(Fault::OutsideMemory);
                uint64_t v = 0;
                if (!pop64(c.e, v)) return fault_code(Fault::OutsideMemory);
                return fault_code(Fault::None); // loading a selector is a no-op here
            }
            case 0xB6: case 0xB7: {
                c.decodeRm();
                if (c.fault != fault_code(Fault::None)) return c.fault;
                const uint64_t v = c.oVal(op2 == 0xB6 ? 1 : 2);
                if (c.fault != fault_code(Fault::None)) return c.fault;
                c.gSet(is64 ? (c.rexW ? 8 : 4) : (c.op66 ? 2 : 4), v);
                if (c.fault != fault_code(Fault::None)) return c.fault;
                return fault_code(Fault::None);
            }
            case 0xBE: case 0xBF: {
                c.decodeRm();
                if (c.fault != fault_code(Fault::None)) return c.fault;
                const int from = (op2 == 0xBE) ? 1 : 2;
                const uint64_t v = c.oVal(from);
                if (c.fault != fault_code(Fault::None)) return c.fault;
                c.gSet(is64 ? (c.rexW ? 8 : 4) : (c.op66 ? 2 : 4), sext(from, v));
                if (c.fault != fault_code(Fault::None)) return c.fault;
                return fault_code(Fault::None);
            }
            case 0xC8: case 0xC9: case 0xCA: case 0xCB: case 0xCC: case 0xCD: case 0xCE: case 0xCF: {
                const int idx = (op2 & 7) | (c.rexB << 3);
                if (c.rexW && is64) {
                    uint64_t v = c.e.r[idx & 15];
                    c.e.r[idx & 15] = _byteswap_uint64(v);
                } else {
                    const uint64_t v = c.e.r[idx & 15] & 0xFFFFFFFFull;
                    c.e.r[idx & 15] = _byteswap_uint64(static_cast<uint64_t>(_byteswap_ulong(static_cast<unsigned long>(v)) & 0xFFFFFFFFull));
                }
                return fault_code(Fault::None);
            }
            default:
                return fault_code(Fault::UnsupportedInstruction);
            }
        }

        default:
            return fault_code(Fault::UnsupportedInstruction);
        }
    }

    // ================= guest exception machinery (iteration 6) =================
    // _CxxThrowException/RaiseException stand-ins record the throw; dispatchFrom
    // walks the logged call frames newest-first, reads .pdata/UNWIND_INFO plus
    // EH4 metadata out of the guest image and launches the catch/filter funclet
    // on a synthetic sentinel return address. Anything the metadata does not
    // fit the supported shapes is a fail-closed fault, never a guessed resume.

    // Guest VA of an image-relative address. The image base is the runtime
    // value the guest declared in its descriptor, never a parsed header.
    static uint64_t ehGva(uint64_t imageBase, uint64_t rva) {
        return imageBase + rva;
    }

    static void ehFail(Loaded& l) {
        l.fault = fault_code(Fault::UnsupportedInstruction);
    }

    static void ehLogCall(Loaded& l, uint64_t ret, uint64_t rspEntry, uint64_t rbp) {
        if (l.ehLogCount < kEhLogMax) {
            l.ehLog[l.ehLogCount].ret = ret;
            l.ehLog[l.ehLogCount].rspEntry = rspEntry;
            l.ehLog[l.ehLogCount].rbp = rbp;
            ++l.ehLogCount;
        }
        // overflow leaves the log short of the real stack; a later throw then
        // walks stale frames and fails closed in dispatchFrom
    }

    // Drops the logged frame for a completed call: exact match on the return
    // address and the slot it lives in (rsp equals the slot after the pop).
    static void ehRetPop(Loaded& l, uint64_t ret, uint64_t rsp) {
        if (l.ehLogCount > 0 &&
            l.ehLog[l.ehLogCount - 1].ret == ret &&
            l.ehLog[l.ehLogCount - 1].rspEntry == rsp)
            --l.ehLogCount;
    }

    // ehdata4_export.h ReadUnsigned: the low nibble of the first byte selects
    // negLength/shift; the value is read from the dword that ends at byte 0.
    static bool eh4ReadUnsigned(Emu& e, uint64_t& p, uint32_t& out) {
        uint8_t b0;
        if (!memLd<uint8_t>(e, p, b0)) return false;
        static const int8_t negLen[16] = {-1,-2,-1,-3,-1,-2,-1,-4,-1,-2,-1,-3,-1,-2,-1,-5};
        static const uint8_t shiftT[16] = {25,18,25,11,25,18,25,4,25,18,25,11,25,18,25,0};
        const int nl = negLen[b0 & 0x0F];
        uint32_t window;
        if (!memLd<uint32_t>(e, p - nl - 4, window)) return false;
        p -= nl; // nl is negative: the cursor advances past the value bytes
        out = (window >> shiftT[b0 & 0x0F]) & 0xFFFFFFFFu;
        return true;
    }

    static bool eh4ReadInt(Emu& e, uint64_t& p, int32_t& out) {
        uint32_t v;
        if (!memLd<uint32_t>(e, p, v)) return false;
        p += 4;
        out = static_cast<int32_t>(v);
        return true;
    }

    // RUNTIME_FUNCTION covering the image RVA of pc (a return address - 1),
    // found by scanning the .pdata table the guest declared in its descriptor.
    // No image declared, or pc outside it: false, the frame is skipped.
    static bool ehFindFunction(Emu& e, uint64_t pcGuest, uint64_t imageBase, uint64_t pdataVa,
                               uint32_t pdataSize,
                               uint32_t& fnBegin, uint32_t& fnEnd, uint32_t& unwindRva) {
        if (imageBase == 0 || pdataVa == 0 || pdataSize < 12) return false;
        if (pcGuest < imageBase) return false;
        const uint64_t rva = pcGuest - imageBase;
        const uint32_t n = pdataSize / 12;
        for (uint32_t i = 0; i < n; ++i) {
            uint32_t b, en, u;
            const uint64_t e3 = pdataVa + 12ull * i;
            if (!memLd<uint32_t>(e, e3, b) ||
                !memLd<uint32_t>(e, e3 + 4, en) ||
                !memLd<uint32_t>(e, e3 + 8, u)) return false;
            if (b <= rva && rva < en) { fnBegin = b; fnEnd = en; unwindRva = u; return true; }
        }
        return false;
    }

    // x86 EH3/SEH3: the FS:[0] registration chain is the authentic walk. Node
    // forms (MSVC 14.x):
    //   C++ EH3: {next, handler thunk, trylevel} - handler = `nop nop; mov
    //            eax,<FuncInfoVA>; jmp [IAT __CxxFrameHandler3]`
    //   SEH3:    {next, handler, scopetable, trylevel} - handler = `jmp [IAT
    //            _except_handler3]`, scopetable entries {enclosing, filter,
    //            handler} indexed by trylevel
    // All metadata fields are link-time VAs; the guest's descriptor gives the
    // runtime image base, so guest VA = link VA - linkBase + runtimeBase.
    // Stack pointers (nodes, ebp) are already runtime VAs.
    static void dispatchFrom86(Loaded& l, Emu& e, uint64_t node) {
        while (node != 0) {
            uint32_t next, handler, third;
            if (!memLd<uint32_t>(e, node, next) ||
                !memLd<uint32_t>(e, node + 4, handler) ||
                !memLd<uint32_t>(e, node + 8, third)) { ehFail(l); return; }
            uint8_t h0, h1;
            if (!memLd<uint8_t>(e, handler, h0) ||
                !memLd<uint8_t>(e, handler + 1, h1)) { ehFail(l); return; }

            if (h0 == 0x90 && h1 == 0x90) {
                // C++ EH3 frame
                uint8_t b2;
                if (!memLd<uint8_t>(e, (handler) + 2, b2) || b2 != 0xB8) { ehFail(l); return; }
                uint32_t funcInfo;
                if (!memLd<uint32_t>(e, (handler) + 3, funcInfo)) { ehFail(l); return; }
                // resolve the personality through the thunk's jmp
                uint8_t j0;
                if (!memLd<uint8_t>(e, (handler) + 7, j0)) { ehFail(l); return; }
                uint32_t slotAddr;
                if (j0 == 0xFF) { // FF 25 addr32
                    if (!memLd<uint32_t>(e, (handler) + 9, slotAddr)) { ehFail(l); return; }
                } else if (j0 == 0xE9) { // E9 rel32 into a jmp [IAT]
                    uint32_t rel;
                    if (!memLd<uint32_t>(e, (handler) + 8, rel)) { ehFail(l); return; }
                    const uint32_t target = handler + 12 + rel;
                    uint8_t j1a, j1b;
                    if (!memLd<uint8_t>(e, (target), j1a) ||
                        !memLd<uint8_t>(e, (target) + 1, j1b) ||
                        j1a != 0xFF || j1b != 0x25 ||
                        !memLd<uint32_t>(e, (target) + 2, slotAddr)) { ehFail(l); return; }
                } else { ehFail(l); return; }
                uint32_t slotVal;
                if (!memLd<uint32_t>(e, (slotAddr), slotVal)) { ehFail(l); return; }
                if (static_cast<uint64_t>(slotVal - l.env.base()) != ST_CXXFRAME3) { ehFail(l); return; }
                if (l.ehThrow.tiPtr == 0) { node = next; continue; } // SEH throw past a C++ frame

                uint32_t magic, maxState, nTB, pTBM;
                int32_t pUW;
                if (!memLd<uint32_t>(e, (funcInfo), magic) ||
                    !memLd<uint32_t>(e, (funcInfo) + 4, maxState) ||
                    !memLd<int32_t>(e, (funcInfo) + 8, pUW) ||
                    !memLd<uint32_t>(e, (funcInfo) + 12, nTB) ||
                    !memLd<uint32_t>(e, (funcInfo) + 16, pTBM)) { ehFail(l); return; }
                (void)pUW; (void)maxState;
                if (magic != 0x19930522) { ehFail(l); return; }
                const uint64_t ebp = node + 0xC;
                const int32_t state = static_cast<int32_t>(third); // trylevel at throw
                for (uint32_t t = 0; t < nTB; ++t) {
                    int32_t tryLow, tryHigh, catchHigh;
                    uint32_t nC, pHandler;
                    if (!memLd<int32_t>(e, (pTBM) + 20ull * t, tryLow) ||
                        !memLd<int32_t>(e, (pTBM) + 20ull * t + 4, tryHigh) ||
                        !memLd<int32_t>(e, (pTBM) + 20ull * t + 8, catchHigh) ||
                        !memLd<uint32_t>(e, (pTBM) + 20ull * t + 12, nC) ||
                        !memLd<uint32_t>(e, (pTBM) + 20ull * t + 16, pHandler)) { ehFail(l); return; }
                    if (state < tryLow || state > tryHigh) continue;
                    for (uint32_t h = 0; h < nC; ++h) {
                        uint32_t adj, pType, aoh;
                        int32_t dispCatch;
                        if (!memLd<uint32_t>(e, (pHandler) + 16ull * h, adj) ||
                            !memLd<uint32_t>(e, (pHandler) + 16ull * h + 4, pType) ||
                            !memLd<int32_t>(e, (pHandler) + 16ull * h + 8, dispCatch) ||
                            !memLd<uint32_t>(e, (pHandler) + 16ull * h + 12, aoh)) { ehFail(l); return; }
                        if (adj != 0) { ehFail(l); return; }
                        bool match = pType == 0; // catch(...)
                        uint32_t matchCt = 0;
                        if (pType != 0) {
                            uint32_t cta;
                            if (!memLd<uint32_t>(e, (l.ehThrow.tiPtr) + 12, cta)) { ehFail(l); return; }
                            uint32_t nCt;
                            if (!memLd<uint32_t>(e, (cta), nCt)) { ehFail(l); return; }
                            for (uint32_t ci = 0; ci < nCt && !match; ++ci) {
                                uint32_t ct;
                                if (!memLd<uint32_t>(e, (cta) + 4 + 4ull * ci, ct)) { ehFail(l); return; }
                                uint32_t ctType;
                                if (!memLd<uint32_t>(e, (ct) + 4, ctType)) { ehFail(l); return; }
                                if (ctType == pType) { match = true; matchCt = ct; }
                            }
                        }
                        if (!match) continue;
                        // catch object copy into the frame (0 = no copy slot)
                        if (pType != 0 && dispCatch != 0) {
                            int32_t mdisp;
                            uint32_t sz;
                            if (!memLd<int32_t>(e, (matchCt) + 8, mdisp) ||
                                !memLd<uint32_t>(e, (matchCt) + 0x14, sz)) { ehFail(l); return; }
                            const uint64_t dst = ebp + static_cast<uint64_t>(dispCatch);
                            const uint64_t src = l.ehThrow.objEA + static_cast<uint64_t>(mdisp);
                            for (uint32_t by = 0; by < sz; ++by) {
                                uint8_t byv;
                                if (!memLd<uint8_t>(e, src + by, byv) ||
                                    !memSt<uint8_t>(e, dst + by, byv)) { ehFail(l); return; }
                            }
                        }
                        // The catch handler is a funclet: the CRT calls it and
                        // its return value (eax) is the continuation address.
                        // Release emits a pure `mov eax,<cont>; ret` thunk (the
                        // catch body is inlined at the continuation); Debug does
                        // the catch work inside the funclet itself. Either way
                        // the funclet runs with the parent's ebp.
                        // nested throws inside the catch must not re-match this try
                        if (!memSt<uint32_t>(e, node + 8, static_cast<uint32_t>(catchHigh))) { ehFail(l); return; }
                        l.eh = EhPending{};
                        l.eh.active = true;
                        l.eh.mode = 3;
                        l.eh.contBase = ebp;
                        uint32_t savedEsp;
                        if (!memLd<uint32_t>(e, ebp - 0x10, savedEsp)) { ehFail(l); return; }
                        e.r[kRBP] = ebp;
                        e.r[kRSP] = savedEsp - 4; // as if the CRT had called it
                        if (!memSt<uint32_t>(e, e.r[kRSP], static_cast<uint32_t>(kSentinelSub))) { ehFail(l); return; }
                        e.ip = aoh;
                        return;
                    }
                }
                node = next;
                continue;
            }

            if (h0 == 0xFF && h1 == 0x25) {
                // SEH3 frame: handler = `jmp dword ptr [IAT]`
                uint32_t slotAddr, slotVal;
                if (!memLd<uint32_t>(e, (handler) + 2, slotAddr) ||
                    !memLd<uint32_t>(e, (slotAddr), slotVal)) { ehFail(l); return; }
                if (static_cast<uint64_t>(slotVal - l.env.base()) != ST_EH3) { ehFail(l); return; }
                if (l.ehThrow.tiPtr != 0) { node = next; continue; } // C++ throw past an SEH frame

                const uint32_t scopetable = third;
                uint32_t lvl;
                if (!memLd<uint32_t>(e, node + 0xC, lvl)) { ehFail(l); return; }
                const int32_t level = static_cast<int32_t>(lvl);
                if (level < 0) { node = next; continue; }
                const uint64_t ebp = node + 0x10;
                uint32_t filter, handlerAddr;
                if (!memLd<uint32_t>(e, (scopetable) + 12ull * level + 4, filter) ||
                    !memLd<uint32_t>(e, (scopetable) + 12ull * level + 8, handlerAddr)) { ehFail(l); return; }
                if (filter == 0) { ehFail(l); return; } // __finally: unsupported
                // EXCEPTION_RECORD + EXCEPTION_POINTERS below the frame; the
                // filter reads the pointer from the fixed [ebp-14h] slot
                const uint32_t er = static_cast<uint32_t>(ebp) - 0xC0;
                const uint32_t ep = static_cast<uint32_t>(ebp) - 0x68;
                if (!memSt<uint32_t>(e, er + 0, static_cast<uint32_t>(l.ehThrow.code)) ||
                    !memSt<uint32_t>(e, er + 4, static_cast<uint32_t>(l.ehThrow.flags)) ||
                    !memSt<uint32_t>(e, er + 8, 0) ||
                    !memSt<uint32_t>(e, er + 0xC, 0) ||
                    !memSt<uint32_t>(e, er + 0x10, l.ehThrow.nargs) ||
                    !memSt<uint32_t>(e, er + 0x14, 0)) { ehFail(l); return; }
                for (uint32_t a = 0; a < l.ehThrow.nargs && a < 15; ++a) {
                    uint32_t av;
                    if (!memLd<uint32_t>(e, l.ehThrow.argsEA + 4ull * a, av) ||
                        !memSt<uint32_t>(e, er + 0x14 + 4ull * a, av)) { ehFail(l); return; }
                }
                if (!memSt<uint32_t>(e, ep, er) || !memSt<uint32_t>(e, ep + 4, 0) ||
                    !memSt<uint32_t>(e, ebp - 0x14, ep)) { ehFail(l); return; }
                l.eh = EhPending{};
                l.eh.active = true;
                l.eh.mode = 2;
                l.eh.contBase = ebp;
                l.eh.contVals[0] = (handlerAddr);
                l.eh.walkFrame = node;
                e.r[kRBP] = ebp;
                e.r[kRSP] = ebp - 0x40;
                if (!memSt<uint32_t>(e, e.r[kRSP], static_cast<uint32_t>(kSentinelSub))) { ehFail(l); return; }
                e.ip = (filter);
                return;
            }

            ehFail(l); // unknown registration node form
            return;
        }
        ehFail(l); // walked the whole chain: nothing handles this throw
    }

    // Walk logged frames newest-first from index `from` and launch the first
    // matching handler. `from` is ehLogCount at throw time; the frame at
    // from-1 is the throw stand-in call itself.
    static void dispatchFrom(Loaded& l, Emu& e, uint32_t from) {
        if constexpr (!is64) {
            // x86: walk the FS:[0] registration chain instead of the call log
            (void)from;
            uint32_t n0;
            if (!memLd<uint32_t>(e, e.fsBase, n0)) { ehFail(l); return; }
            dispatchFrom86(l, e, n0);
            return;
        }
        // The guest declares its image layout in the descriptor globals; a
        // blob that registered nothing has no unwind metadata to walk.
        uint64_t imageBase = 0, pdataVa = 0;
        uint32_t pdataSize = 0;
        {
            const uint64_t d = e.envBase + kDescRva;
            uint32_t magic;
            if (!memLd<uint32_t>(e, d, magic) || magic != kDescMagic ||
                !memLd<uint64_t>(e, d + 8, imageBase) ||
                !memLd<uint64_t>(e, d + 0x10, pdataVa) ||
                !memLd<uint32_t>(e, d + 0x18, pdataSize)) {
                ehFail(l); return;
            }
        }
        for (uint32_t k = from; k > 0; --k) {
            const uint64_t ret = l.ehLog[k - 1].ret;
            const uint64_t estRsp = l.ehLog[k - 1].rspEntry + 8;
            uint32_t fnBegin, fnEnd, unwindRva;
            if (!ehFindFunction(e, ret - 1, imageBase, pdataVa, pdataSize, fnBegin, fnEnd, unwindRva)) continue;
            const uint64_t rva = ret - 1 - imageBase;
            uint8_t b0;
            if (!memLd<uint8_t>(e, ehGva(imageBase, unwindRva), b0)) { ehFail(l); return; }
            const uint32_t ver = b0 & 7;
            if (ver != 1 && ver != 2) { ehFail(l); return; }
            const uint32_t flags = (b0 >> 3) & 0x1F;
            if (flags & 4) { ehFail(l); return; }   // chained unwind info
            if (!(flags & 3)) continue;             // funclet/leaf: no personality
            uint8_t cnt;
            if (!memLd<uint8_t>(e, ehGva(imageBase, unwindRva) + 2, cnt)) { ehFail(l); return; }
            const uint64_t hOff = ehGva(imageBase, unwindRva) + 4 + 2ull * cnt + ((cnt & 1) ? 2 : 0);
            uint32_t hRva, dRva;
            if (!memLd<uint32_t>(e, hOff, hRva) ||
                !memLd<uint32_t>(e, hOff + 4, dRva)) { ehFail(l); return; }
            // personality: thunk `jmp [IAT]` -> slot -> stand-in kind
            uint8_t j0, j1;
            if (!memLd<uint8_t>(e, ehGva(imageBase, hRva), j0) ||
                !memLd<uint8_t>(e, ehGva(imageBase, hRva) + 1, j1) ||
                j0 != 0xFF || j1 != 0x25) { ehFail(l); return; }
            uint32_t relU;
            if (!memLd<uint32_t>(e, ehGva(imageBase, hRva) + 2, relU)) { ehFail(l); return; }
            const uint64_t slotRva = hRva + 6 + static_cast<uint64_t>(static_cast<int64_t>(static_cast<int32_t>(relU)));
            uint64_t slotVal;
            if (!memLd<uint64_t>(e, ehGva(imageBase, slotRva), slotVal)) { ehFail(l); return; }
            const uint64_t kind = slotVal - l.env.base();

            if (l.ehThrow.tiPtr != 0) {
                // C++ throw: only __CxxFrameHandler4 frames participate (FH3 is x86)
                if (kind != ST_CXXFRAME4) continue;
                // FuncInfo4 at dRva
                uint64_t p = ehGva(imageBase, dRva);
                uint8_t fh;
                if (!memLd<uint8_t>(e, p++, fh)) { ehFail(l); return; }
                if (fh & 0x80) { ehFail(l); return; }          // reserved
                if (fh & 0x02) { ehFail(l); return; }          // separated code
                uint32_t cu;
                if (fh & 0x04 && !eh4ReadUnsigned(e, p, cu)) { ehFail(l); return; }  // BBT flags
                int32_t i32v;
                if (fh & 0x08 && !eh4ReadInt(e, p, i32v)) { ehFail(l); return; }     // unwind map (unused)
                int32_t tbmRva = 0;
                if (fh & 0x10 && !eh4ReadInt(e, p, tbmRva)) { ehFail(l); return; }
                int32_t ip2Rva;
                if (!eh4ReadInt(e, p, ip2Rva)) { ehFail(l); return; }
                if (fh & 0x01 && !eh4ReadUnsigned(e, p, cu)) { ehFail(l); return; }  // dispFrame
                // current state at the throw point (entries store state+1)
                uint32_t state = 0xFFFFFFFF; // -1
                {
                    uint64_t q = ehGva(imageBase, static_cast<uint32_t>(ip2Rva));
                    uint32_t n2, prev = 0;
                    if (!eh4ReadUnsigned(e, q, n2)) { ehFail(l); return; }
                    for (uint32_t i = 0; i < n2; ++i) {
                        uint32_t d, st;
                        if (!eh4ReadUnsigned(e, q, d) || !eh4ReadUnsigned(e, q, st)) { ehFail(l); return; }
                        prev += d;
                        if (prev <= rva - fnBegin) state = st - 1; else break;
                    }
                }
                if (tbmRva == 0 || state == 0xFFFFFFFF) continue;
                uint64_t q = ehGva(imageBase, static_cast<uint32_t>(tbmRva));
                uint32_t nT;
                if (!eh4ReadUnsigned(e, q, nT)) { ehFail(l); return; }
                for (uint32_t t = 0; t < nT; ++t) {
                    uint32_t lo, hi, chigh;
                    int32_t hArr;
                    if (!eh4ReadUnsigned(e, q, lo) || !eh4ReadUnsigned(e, q, hi) ||
                        !eh4ReadUnsigned(e, q, chigh) || !eh4ReadInt(e, q, hArr)) { ehFail(l); return; }
                    if (state < lo || state > hi) continue;
                    uint64_t hq = ehGva(imageBase, static_cast<uint32_t>(hArr));
                    uint32_t nH;
                    if (!eh4ReadUnsigned(e, hq, nH)) { ehFail(l); return; }
                    for (uint32_t h = 0; h < nH; ++h) {
                        uint8_t hv;
                        if (!memLd<uint8_t>(e, hq++, hv)) { ehFail(l); return; }
                        uint32_t dispCatch = 0;
                        int32_t dispType = 0;
                        const bool hasType = (hv >> 1) & 1;
                        const bool hasObj = (hv >> 2) & 1;
                        if (hv & 1) { if (!eh4ReadUnsigned(e, hq, cu)) { ehFail(l); return; } }
                        if (hasType && !eh4ReadInt(e, hq, dispType)) { ehFail(l); return; }
                        if (hasObj && !eh4ReadUnsigned(e, hq, dispCatch)) { ehFail(l); return; }
                        int32_t funclet;
                        if (!eh4ReadInt(e, hq, funclet)) { ehFail(l); return; }
                        const uint32_t contCount = (hv >> 4) & 3;
                        const bool contIsRva = (hv >> 3) & 1;
                        uint32_t cont0 = 0;
                        if (contCount >= 1) {
                            if (contIsRva) {
                                if (!memLd<uint32_t>(e, hq, cont0)) { ehFail(l); return; }
                                hq += 4;
                            } else if (!eh4ReadUnsigned(e, hq, cont0)) { ehFail(l); return; }
                            for (uint32_t cc = 1; cc < contCount; ++cc) {
                                if (contIsRva) hq += 4;
                                else if (!eh4ReadUnsigned(e, hq, cu)) { ehFail(l); return; }
                            }
                        }
                        // type match: exact TD RVA equality with a thrown CT
                        uint32_t matchCt = 0;
                        bool match = !hasType; // catch(...)
                        if (hasType) {
                            const uint32_t tiRva = static_cast<uint32_t>(l.ehThrow.tiPtr - imageBase);
                            uint32_t cta;
                            if (!memLd<uint32_t>(e, ehGva(imageBase, tiRva) + 12, cta)) { ehFail(l); return; }
                            uint32_t nC;
                            if (!memLd<uint32_t>(e, ehGva(imageBase, cta), nC)) { ehFail(l); return; }
                            for (uint32_t ci = 0; ci < nC && !match; ++ci) {
                                uint32_t ctRva;
                                if (!memLd<uint32_t>(e, ehGva(imageBase, cta) + 4 + 4ull * ci, ctRva)) { ehFail(l); return; }
                                uint32_t td;
                                if (!memLd<uint32_t>(e, ehGva(imageBase, ctRva) + 4, td)) { ehFail(l); return; }
                                if (td == static_cast<uint32_t>(dispType)) { match = true; matchCt = ctRva; }
                            }
                        }
                        if (!match) continue;
                        if (contCount > 1) { ehFail(l); return; } // multi-continuation unsupported
                        // CatchableType: {props, dispType, mdisp, pdisp, vdisp, sizeOrOffset}
                        if (hasObj) {
                            int32_t mdisp;
                            uint32_t sz;
                            if (!memLd<uint32_t>(e, ehGva(imageBase, matchCt) + 8, *reinterpret_cast<uint32_t*>(&mdisp)) ||
                                !memLd<uint32_t>(e, ehGva(imageBase, matchCt) + 0x14, sz)) { ehFail(l); return; }
                            const uint64_t dst = estRsp + dispCatch;
                            const uint64_t src = l.ehThrow.objEA + static_cast<uint64_t>(mdisp);
                            for (uint32_t by = 0; by < sz; ++by) {
                                uint8_t byv;
                                if (!memLd<uint8_t>(e, src + by, byv) ||
                                    !memSt<uint8_t>(e, dst + by, byv)) { ehFail(l); return; }
                            }
                        }
                        // launch the catch funclet on a synthetic sentinel return
                        l.ehLogCount = k - 1; // drop this frame and everything newer
                        l.eh = EhPending{};
                        l.eh.active = true;
                        l.eh.mode = 1;
                        l.eh.estRsp = estRsp;
                        l.eh.logMark = k - 1;
                        if (contCount == 1) {
                            l.eh.contKind = 1;
                            l.eh.contVals[0] = contIsRva ? ehGva(imageBase, cont0)
                                                         : ehGva(imageBase, fnBegin + cont0);
                        }
                        e.r[kRSP] = estRsp - 8;
                        if (!memSt<uint64_t>(e, e.r[kRSP], kSentinelSub)) { ehFail(l); return; }
                        e.r[1] = hasObj ? estRsp + dispCatch : l.ehThrow.objEA; // rcx
                        e.r[2] = estRsp;                                        // rdx
                        // real unwinding restores callee-saved rbp per frame;
                        // Debug continuations address locals via the frame's rbp
                        e.r[kRBP] = l.ehLog[k - 1].rbp;
                        e.ip = ehGva(imageBase, static_cast<uint32_t>(funclet));
                        return;
                    }
                }
                continue; // no catch in this frame
            }

            // SEH throw (RaiseException): __C_specific_handler frames only
            if (kind != ST_CSH) continue;
            // the scope table follows the handler RVA inline in UNWIND_INFO
            uint64_t q = hOff + 4;
            uint32_t nS;
            if (!memLd<uint32_t>(e, q, nS) || nS > 64) { ehFail(l); return; }
            for (uint32_t s = 0; s < nS; ++s) {
                uint32_t sb, se, sf, sh;
                const uint64_t sq = q + 4 + 16ull * s;
                if (!memLd<uint32_t>(e, sq, sb) || !memLd<uint32_t>(e, sq + 4, se) ||
                    !memLd<uint32_t>(e, sq + 8, sf) || !memLd<uint32_t>(e, sq + 12, sh)) { ehFail(l); return; }
                if (rva < sb || rva >= se) continue;
                if (sf == 0) { ehFail(l); return; } // __finally: unsupported
                // materialize EXCEPTION_RECORD64 + EXCEPTION_POINTERS below the
                // funclet frame; the filter only reads the code through [rcx]
                const uint64_t er = estRsp - 0x100;
                const uint64_t ep = estRsp - 0xE0;
                if (!memSt<uint32_t>(e, er + 0, static_cast<uint32_t>(l.ehThrow.code)) ||
                    !memSt<uint32_t>(e, er + 4, static_cast<uint32_t>(l.ehThrow.flags)) ||
                    !memSt<uint64_t>(e, er + 8, 0) ||
                    !memSt<uint64_t>(e, er + 0x10, 0) ||
                    !memSt<uint32_t>(e, er + 0x18, l.ehThrow.nargs) ||
                    !memSt<uint32_t>(e, er + 0x1C, 0)) { ehFail(l); return; }
                for (uint32_t a = 0; a < l.ehThrow.nargs && a < 15; ++a) {
                    uint64_t av;
                    if (!memLd<uint64_t>(e, l.ehThrow.argsEA + 8ull * a, av) ||
                        !memSt<uint64_t>(e, er + 0x20 + 8ull * a, av)) { ehFail(l); return; }
                }
                if (!memSt<uint64_t>(e, ep, er) || !memSt<uint64_t>(e, ep + 8, 0)) { ehFail(l); return; }
                l.ehLogCount = k - 1;
                l.eh = EhPending{};
                l.eh.active = true;
                l.eh.mode = 2;
                l.eh.estRsp = estRsp;
                l.eh.logMark = k - 1;
                l.eh.contKind = 1;
                l.eh.contVals[0] = ehGva(imageBase, sh); // handler resume IP
                e.r[kRSP] = estRsp - 8;
                if (!memSt<uint64_t>(e, e.r[kRSP], kSentinelSub)) { ehFail(l); return; }
                e.r[1] = ep;     // rcx = EXCEPTION_POINTERS*
                e.r[2] = estRsp; // rdx = establisher frame rsp
                e.ip = ehGva(imageBase, sf);
                return;
            }
            continue;
        }
        // walked every frame: nothing handles this throw
        ehFail(l);
    }

    // A funclet returned: its ret popped kSentinelSub. Finish the pending
    // catch, or continue the SEH walk with the filter's verdict in RAX.
    static void ehResume(Loaded& l, Emu& e) {
        l.ehLogCount = l.eh.logMark;
        if (l.eh.mode == 1) {
            l.eh.active = false;
            e.r[kRSP] = l.eh.estRsp;
            if (l.eh.contKind == 1) {
                e.ip = l.eh.contVals[0];
            } else {
                // contCount == 0: the funclet returned the continuation
                // address in rax directly (Debug codegen)
                e.ip = e.r[0];
            }
            return;
        }
        if (l.eh.mode == 2) {
            if constexpr (is64) {
                const uint64_t verdict = e.r[0];
                l.eh.active = false;
                if (verdict == 1) {            // EXCEPTION_EXECUTE_HANDLER
                    e.r[kRSP] = l.eh.estRsp;
                    e.ip = l.eh.contVals[0];
                    return;
                }
                if (verdict == 0) {            // EXCEPTION_CONTINUE_SEARCH: keep walking
                    dispatchFrom(l, e, l.ehLogCount);
                    return;
                }
                ehFail(l);                     // -1 (continue execution): unsupported
                return;
            }
            // x86 SEH3: the filter ran as a sub-run; its verdict is in eax
            const uint32_t verdict = static_cast<uint32_t>(e.r[0]);
            l.eh.active = false;
            if (verdict == 1) {                // EXCEPTION_EXECUTE_HANDLER
                e.r[kRBP] = l.eh.contBase;
                // the generated __except body restores esp itself
                e.r[kRSP] = l.eh.contBase - 0x100;
                e.ip = l.eh.contVals[0];
                return;
            }
            if (verdict == 0) {                // EXCEPTION_CONTINUE_SEARCH: next node
                uint32_t next;
                if (!memLd<uint32_t>(e, l.eh.walkFrame, next)) { ehFail(l); return; }
                dispatchFrom86(l, e, next);
                return;
            }
            ehFail(l);                         // -1 (continue execution): unsupported
            return;
        }
        if (l.eh.mode == 3) {
            // x86 C++ EH3: the catch funclet returned the continuation in eax
            const uint32_t cont = static_cast<uint32_t>(e.r[0]);
            l.eh.active = false;
            e.r[kRBP] = l.eh.contBase;
            uint32_t savedEsp;
            if (!memLd<uint32_t>(e, l.eh.contBase - 0x10, savedEsp)) { ehFail(l); return; }
            e.r[kRSP] = savedEsp; // _JumpToContinuation restores the saved ESP
            e.ip = cont;
            return;
        }
        ehFail(l);
    }

    static uint32_t runLoop(Emu& e) {
        Loaded& l = *e.l;
        for (;;) {
            if constexpr (is64) {
                if (e.ip == kSentinel) break;
                if (e.ip == kSentinelSub && l.eh.active) {
                    ehResume(l, e);
                    if (l.fault != fault_code(Fault::None)) {
                        return l.fault;
                    }
                    continue;
                }
            } else {
                if (e.ip == (kSentinel & 0xFFFFFFFFull)) break;
                if (e.ip == (kSentinelSub & 0xFFFFFFFFull) && l.eh.active) {
                    ehResume(l, e);
                    if (l.fault != fault_code(Fault::None)) return l.fault;
                    continue;
                }
            }
            if (const ApiEntry* api = l.apis.find(e.ip)) {
                // compiled-in stand-in; the calling convention is per-arch
                uint64_t ret = 0;
                if constexpr (is64) {
                    // x64 MS ABI: caller cleans stack
                    if (!memLd<uint64_t>(e, e.r[kRSP], ret)) {
                        return fault_code(Fault::OutsideMemory);
                    }
                    e.r[kRSP] += 8; // [rsp+0x28] arg5 at call entry = [rsp+0x20] here
                    uint64_t args[8] = { e.r[1], e.r[2], e.r[8], e.r[9], 0, 0, 0, 0 };
                    for (int i = 4; i < api->nargs && i < 8; ++i) {
                        if (!memLd<uint64_t>(e, e.r[kRSP] + 0x20 + 8 * (i - 4), args[i])) {
                            return fault_code(Fault::OutsideMemory);
                        }
                    }
                    e.r[0] = api->fn(l, args);
                } else {
                    // stdcall: callee pops ret + args (cdecl marks callerCleans)
                    uint64_t args[8] = { 0, 0, 0, 0, 0, 0, 0, 0 };
                    for (int i = 0; i < api->nargs && i < 8; ++i) {
                        uint32_t a = 0;
                        if (!memLd<uint32_t>(e, e.r[4] + 4 + 4 * i, a)) return fault_code(Fault::OutsideMemory);
                        args[i] = a;
                    }
                    uint32_t ret32 = 0;
                    if (!memLd<uint32_t>(e, e.r[4], ret32)) return fault_code(Fault::OutsideMemory);
                    ret = ret32;
                    e.r[4] += api->callerCleans ? 4 : 4 * (1 + api->nargs);
                    e.r[0] = static_cast<uint32_t>(api->fn(l, args));
                }
                if (l.tailJump) {
                    // the stand-in handed control to guest code that ends with
                    // a ret to the stand-in's own return address; the x64
                    // dispatch already popped it, so push it back
                    if constexpr (is64) {
                        e.r[kRSP] -= 8;
                        if (!memSt<uint64_t>(e, e.r[kRSP], ret)) {
                            return fault_code(Fault::OutsideMemory);
                        }
                    }
                    e.ip = l.tailJump;
                    l.tailJump = 0;
                    continue;
                }
                if (l.fault != fault_code(Fault::None)) {
                    return l.fault;
                }
                if (l.ehThrow.active) {
                    // the throw stand-ins never "return": dispatch the guest
                    // exception instead of continuing at the return address
                    l.ehThrow.active = false;
                    dispatchFrom(l, e, l.ehLogCount);
                    if (l.fault != fault_code(Fault::None)) {
                        return l.fault;
                    }
                    continue;
                }
                ehRetPop(l, ret, e.r[kRSP]);
                e.ip = ret;
                continue;
            }
            if (e.budget == 0) return fault_code(Fault::Budget);
            // batch D: call/jmp into a whitelisted real system module runs a
            // native bridge (esp/rsp adjusted as the real callee cleans);
            // anything else stays fail-closed fetch-outside-image.
            const uint64_t trampBase = l.env.base() + ST_TRAMP;
            const bool inTramp = e.ip >= trampBase && e.ip < trampBase + 0x28;
            if ((e.ip < l.img.base() || e.ip >= e.imgEnd) && !inTramp) {
                if (isNativeModuleAddr(l, e.ip)) {
                    --e.budget;
                    uint64_t ret = 0;
                    if constexpr (is64) {
                        if (!memLd<uint64_t>(e, e.r[kRSP], ret)) {
                            return fault_code(Fault::OutsideMemory);
                        }
                        e.r[kRSP] += 8;
                        uint64_t args[16] = { e.r[1], e.r[2], e.r[8], e.r[9], 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
                        for (int i = 4; i < 16; ++i) {
                            uint64_t v;
                            if (memLd<uint64_t>(e, e.r[kRSP] + 0x20 + 8 * (i - 4), v)) args[i] = v;
                        }
                        uint64_t out = 0;
                        if (!callNativeWin64(e.ip, args, out)) return fault_code(Fault::NativeFault);
                        e.r[0] = out;
                    } else {
                        uint32_t args[16] = {};
                        for (int i = 0; i < 16; ++i) {
                            uint32_t v;
                            if (memLd<uint32_t>(e, e.r[kRSP] + 4 + 4 * i, v)) args[i] = v;
                        }
                        uint32_t ret32 = 0, nargs = 0, out = 0;
                        if (!memLd<uint32_t>(e, e.r[kRSP], ret32)) return fault_code(Fault::OutsideMemory);
                        if (!callNativeWin86(e.ip, args, out, nargs)) return fault_code(Fault::NativeFault);
                        e.r[0] = static_cast<uint32_t>(out);
                        // stdcall: callee popped ret + nargs dwords; a cdecl
                        // callee measures nargs = 0 and the guest cleans its
                        // own args afterwards
                        e.r[kRSP] += 4 * (1 + nargs);
                        ret = ret32;
                    }
                    ehRetPop(l, ret, e.r[kRSP]);
                    e.ip = ret;
                    continue;
                }
                fprintf(stderr, "instruction fetch outside image: ip=0x%llX (off=0x%llX)\n",
                        (unsigned long long)e.ip,
                        (unsigned long long)(e.ip - l.img.base()));
                return fault_code(Fault::OutsideMemory);
            }
            --e.budget;
            Fetch f = inTramp
                ? Fetch{l.env.data() + ST_TRAMP, 0x28, static_cast<size_t>(e.ip - trampBase), trampBase}
                : Fetch{l.img.data(), static_cast<size_t>(l.img.size()), static_cast<size_t>(e.ip - l.img.base()), l.img.base()};
            Ctx c{e, l, f};
            uint32_t r = stepOne(c);
            if (r == fault_code(Fault::None) && c.f.fault != fault_code(Fault::None))
                r = c.f.fault; // fetch past image end: same fetch-outside-image fault
            if (r != fault_code(Fault::None)) {
                if (r == fault_code(Fault::Halt)) break; // stub chain end: exit code = EAX
                if (r == fault_code(Fault::OutsideMemory)) {
                    fprintf(stderr, "fault: access outside emulated memory at ip=0x%llX (off=0x%llX)\n",
                            static_cast<unsigned long long>(e.ip),
                            static_cast<unsigned long long>(e.ip - l.img.base()));
                }
                if (r == fault_code(Fault::UnsupportedInstruction)) {
                    fprintf(stderr, "fault: unimplemented opcode at ip=0x%llX (off=0x%llX)\n",
                            static_cast<unsigned long long>(e.ip),
                            static_cast<unsigned long long>(e.ip - l.img.base()));
                }
                if (r == fault_code(Fault::NativeFault)) {
                    fprintf(stderr, "fault: native bridge call escaped via exception at ip=0x%llX\n",
                            static_cast<unsigned long long>(e.ip));
                }
                return r;
            }
            if (!c.ipSet) {
                e.ip = f.ipBase + f.pos;
            }
        }
        return fault_code(Fault::None);
    }

    static void initEntry(Loaded& l, uint64_t stkEnd, Emu& e) {
        e.l = &l;
        e.imgEnd = l.img.base() + l.img.size();
        e.stkEnd = stkEnd;
        e.fsBase = l.fsBase;
        e.gsBase = l.gsBase;
        e.envBase = l.env.base();
        e.envEnd = l.env.base() + l.env.size();
        e.budget = instructionBudget();
    }

public:
    // Main guest entry: full stack, sentinel return address. The blob's own
    // prologue (if any) sets up anything image-specific, e.g. DllMain args.
    static uint32_t runMain(Loaded& l) {
        Emu e;
        initEntry(l, l.stk.base() + l.stk.size(), e);

        // leave 0x100 bytes above the initial rsp: stand-in interception may peek
        // at unused vararg slots, and reads must stay inside the region
        e.r[kRSP] = e.stkEnd - (is64 ? 8 : 4) - 0x100;
        if constexpr (is64) {
            if (!memSt<uint64_t>(e, e.r[kRSP], kSentinel)) return fault_code(Fault::OutsideMemory);
        } else {
            if (!memSt<uint32_t>(e, e.r[kRSP], static_cast<uint32_t>(kSentinel))) return fault_code(Fault::OutsideMemory);
        }
        e.ip = l.img.base();

        const uint32_t r = runLoop(e);
        if (r != fault_code(Fault::None) && r != fault_code(Fault::Halt)) return r;
        return static_cast<uint32_t>(e.r[0] & 0xFFFFFFFFull);
    }

    // Guest thread entry: sentinel return address on top, thread argument
    // in the first argument register (x64 MS ABI) or at [esp+4] (stdcall).
    static uint32_t runThread(Loaded& l, ThreadContext& t) {
        Emu e;
        initEntry(l, t.stack.base() + t.stack.size(), e);
        e.r[kRSP] = e.stkEnd - (is64 ? 8 : 4) - 0x100;
        if constexpr (is64) {
            if (!memSt<uint64_t>(e, e.r[kRSP], kSentinel)) return fault_code(Fault::OutsideMemory);
            e.r[1] = t.arg;
        } else {
            if (!memSt<uint32_t>(e, e.r[kRSP], static_cast<uint32_t>(kSentinel))) return fault_code(Fault::OutsideMemory);
            if (!memSt<uint32_t>(e, e.r[kRSP] + 4, static_cast<uint32_t>(t.arg))) return fault_code(Fault::OutsideMemory);
        }
        e.ip = t.entry;

        const uint32_t r = runLoop(e);
        // Halt ends a thread the same way it ends main: exit code = EAX
        // (ExitThread stand-in rides the halt; the join/wait stand-in
        // records this as the thread's exitCode)
        if (r != fault_code(Fault::None) && r != fault_code(Fault::Halt)) return r;
        return static_cast<uint32_t>(e.r[0] & 0xFFFFFFFFull);
    }
};

} // namespace stub

