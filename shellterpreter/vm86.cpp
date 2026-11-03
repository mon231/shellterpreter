#include "vm.hpp"
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cstdio>
#include <cstring>

namespace stub {
namespace x86 {

enum Reg {
    kRAX = 0, kRCX, kRDX, kRBX, kRSP, kRBP, kRSI, kRDI,
    kR8, kR9, kR10, kR11, kR12, kR13, kR14, kR15, kNumReg
};

constexpr uint64_t kInstrBudget = 5000000000ull;

struct Emu {
    uint64_t r[kNumReg] = {};
    uint64_t ip = 0;
    bool cf = false, of = false, sf = false, zf = false, pf = false, af = false, df = false;
    Loaded* l = nullptr;
    uint64_t imgEnd = 0, stkEnd = 0;
    uint64_t fsBase = 0, envBase = 0, envEnd = 0;
    uint64_t budget = kInstrBudget;
    uint64_t xmm[8][2] = {}; // SSE regs: only movlpd/xorps data flow the CRT uses
};

inline unsigned popcnt8(uint8_t v) {
    unsigned n = 0;
    while (v) { n += v & 1; v >>= 1; }
    return n;
}
constexpr uint64_t kWmask[9] = { 0, 0xFF, 0xFFFF, 0, 0xFFFFFFFFull, 0, 0, 0, ~0ull };
constexpr unsigned kWbits[9] = { 0, 8, 16, 0, 32, 0, 0, 0, 64 };
inline uint64_t maskSz(int sz) { return kWmask[sz]; }
inline unsigned bitsSz(int sz) { return kWbits[sz]; }

inline void flagsLogic(Emu& e, int sz, uint64_t res) {
    e.cf = e.of = false;
    res &= maskSz(sz);
    e.zf = res == 0;
    e.sf = (res & (1ull << (bitsSz(sz) - 1))) != 0;
    e.pf = (popcnt8(static_cast<uint8_t>(res & 0xFF)) % 2) == 0;
}
inline uint64_t doAdd(Emu& e, int sz, uint64_t a, uint64_t b) {
    const uint64_t sum = (a & maskSz(sz)) + (b & maskSz(sz));
    const uint64_t res = sum & maskSz(sz);
    e.cf = (sum >> bitsSz(sz)) != 0;
    const uint64_t sign = 1ull << (bitsSz(sz) - 1);
    e.of = (((a ^ res) & (b ^ res)) & sign) != 0;
    e.af = ((a ^ b ^ res) & 0x10) != 0;
    flagsLogic(e, sz, res);
    return res;
}
inline void flagsNZP(Emu& e, int sz, uint64_t res);
inline uint64_t doSubF(Emu& e, int sz, uint64_t a, uint64_t b) {
    const uint64_t aa = a & maskSz(sz), bb = b & maskSz(sz);
    const uint64_t res = (aa - bb) & maskSz(sz);
    e.cf = aa < bb;
    const uint64_t sign = 1ull << (bitsSz(sz) - 1);
    e.of = (((aa ^ bb) & (aa ^ res)) & sign) != 0;
    e.af = ((aa ^ bb ^ res) & 0x10) != 0;
    flagsNZP(e, sz, res); // keep borrow in cf; flagsLogic would clear it
    return res;
}

inline uint64_t doLogicOp(Emu& e, int sz, uint64_t res) { flagsLogic(e, sz, res); return res & maskSz(sz); }
inline uint64_t doIncOp(Emu& e, int sz, uint64_t a) { const bool c = e.cf; const uint64_t res = doAdd(e, sz, a, 1); e.cf = c; return res; }
inline uint64_t doDecOp(Emu& e, int sz, uint64_t a) { const bool c = e.cf; const uint64_t res = doSubF(e, sz, a, 1); e.cf = c; return res; }
inline uint64_t doNegOp(Emu& e, int sz, uint64_t a) {
    const uint64_t aa = a & maskSz(sz);
    const uint64_t res = (0 - aa) & maskSz(sz);
    e.cf = aa != 0;
    const uint64_t sign = 1ull << (bitsSz(sz) - 1);
    e.of = ((aa & sign) != 0) && ((res & sign) != 0);
    flagsLogic(e, sz, res);
    return res;
}

template <class T> uint8_t* addrPtr(Emu& e, uint64_t addr) {
    if (addr >= e.l->img.base() && addr + sizeof(T) <= e.imgEnd)
        return e.l->img.data() + (addr - e.l->img.base());
    if (addr >= e.l->stk.base() && addr + sizeof(T) <= e.l->stk.base() + e.l->stk.size())
        return e.l->stk.data() + (addr - e.l->stk.base());
    if (addr >= e.envBase && addr + sizeof(T) <= e.envEnd)
        return e.l->env.data() + (addr - e.envBase);
    if (addr >= e.l->heap.base() && addr + sizeof(T) <= e.l->heapEnd)
        return e.l->heap.data() + (addr - e.l->heap.base());
    for (uint32_t i = 0; i < e.l->threadCount; ++i) {
        const GuestRegion& stack = e.l->threads[i].stack;
        if (addr >= stack.base() && addr + sizeof(T) <= stack.base() + stack.size())
            return stack.data() + (addr - stack.base());
    }
    return nullptr;
}
template <class T> bool memLd(Emu& e, uint64_t addr, T& out) {
    uint8_t* p = addrPtr<T>(e, addr);
    if (!p) return false;
    memcpy(&out, p, sizeof(T));
    return true;
}
template <class T> bool memSt(Emu& e, uint64_t addr, T v) {
    uint8_t* p = addrPtr<T>(e, addr);
    if (!p) return false;
    memcpy(p, &v, sizeof(T));
    return true;
}
inline bool push64(Emu& e, uint64_t v) {
    constexpr uint64_t m = 0xFFFFFFFFull;
    const uint64_t addr = e.r[kRSP] - 4;
    if (!memSt<uint32_t>(e, addr, static_cast<uint32_t>(v & m))) return false;
    e.r[kRSP] = addr;
    return true;
}
inline bool pop64(Emu& e, uint64_t& v) {
    uint32_t w = 0;
    if (!memLd(e, e.r[kRSP], w)) return false;
    e.r[kRSP] += 4;
    v = w;
    return true;
}

struct Fetch {
    const uint8_t* data; size_t len; size_t pos;
    uint8_t u8() { return data[pos++]; }
    uint16_t u16() { uint16_t v; memcpy(&v, data + pos, 2); pos += 2; return v; }
    uint32_t u32() { uint32_t v; memcpy(&v, data + pos, 4); pos += 4; return v; }
    uint64_t u64() { uint64_t v; memcpy(&v, data + pos, 8); pos += 8; return v; }
};

struct MR {
    int mod = 3, reg = 0, rm = 0;
    bool hasSib = false;
    int sibBase = 0, sibIndex = 0, sibScale = 0;
    int64_t disp = 0;
    bool absDisp = false;
};

uint32_t decodeMR(Fetch& f, MR& m) {
    const uint8_t byte = f.u8();
    m.mod = byte >> 6;
    m.reg = (byte >> 3) & 7;
    m.rm = byte & 7;
    m.hasSib = false;
    m.absDisp = false;
    m.disp = 0;
    if (m.mod == 3) return fault_code(Fault::None);
    if (m.rm == 4) {
        m.hasSib = true;
        const uint8_t sib = f.u8();
        m.sibScale = sib >> 6;
        m.sibIndex = (sib >> 3) & 7;
        m.sibBase = sib & 7;
        if (m.sibBase == 5 && m.mod == 0) { m.disp = static_cast<int64_t>(f.u32()); return fault_code(Fault::None); }
        if (m.mod == 1) m.disp = static_cast<int8_t>(f.u8());
        else if (m.mod == 2) m.disp = static_cast<int32_t>(f.u32());
        return fault_code(Fault::None);
    }
    if (m.rm == 5 && m.mod == 0) { m.absDisp = true; m.disp = static_cast<int64_t>(f.u32()); return fault_code(Fault::None); }
    if (m.mod == 1) m.disp = static_cast<int8_t>(f.u8());
    else if (m.mod == 2) m.disp = static_cast<int32_t>(f.u32());
    return fault_code(Fault::None);
}

inline bool cond(Emu& e, uint8_t cc) {
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

struct Oprm {
    bool isReg;
    int regIdx;
    uint64_t addr;
};

uint64_t oRead(Emu& e, const Oprm& o, int sz, uint32_t& fault) {
    if (o.isReg) return e.r[o.regIdx & 15] & maskSz(sz);
    switch (sz) {
    case 1: { uint8_t v; if (!memLd(e, o.addr, v)) { fault = fault_code(Fault::OutsideMemory); return 0; } return v; }
    case 2: { uint16_t v; if (!memLd(e, o.addr, v)) { fault = fault_code(Fault::OutsideMemory); return 0; } return v; }
    case 4: { uint32_t v; if (!memLd(e, o.addr, v)) { fault = fault_code(Fault::OutsideMemory); return 0; } return v; }
    case 8: { uint64_t v; if (!memLd(e, o.addr, v)) { fault = fault_code(Fault::OutsideMemory); return 0; } return v; }
    }
    fault = fault_code(Fault::UnsupportedInstruction); return 0;
}
void oWrite(Emu& e, const Oprm& o, int sz, uint64_t v, uint32_t& fault) {
    if (o.isReg) {
        if (sz == 4) { e.r[o.regIdx & 15] = v & 0xFFFFFFFFull; return; }
        const uint64_t keep = ~maskSz(sz);
        e.r[o.regIdx & 15] = (e.r[o.regIdx & 15] & keep) | (v & maskSz(sz));
        return;
    }
    switch (sz) {
    case 1: if (!memSt(e, o.addr, static_cast<uint8_t>(v))) fault = fault_code(Fault::OutsideMemory); break;
    case 2: if (!memSt(e, o.addr, static_cast<uint16_t>(v))) fault = fault_code(Fault::OutsideMemory); break;
    case 4: if (!memSt(e, o.addr, static_cast<uint32_t>(v))) fault = fault_code(Fault::OutsideMemory); break;
    case 8: if (!memSt(e, o.addr, v)) fault = fault_code(Fault::OutsideMemory); break;
    default: fault = fault_code(Fault::UnsupportedInstruction); break;
    }
}

inline uint64_t sext(int from, uint64_t v) {
    switch (from) {
    case 1: return static_cast<uint64_t>(static_cast<int64_t>(static_cast<int8_t>(v & 0xFF)));
    case 2: return static_cast<uint64_t>(static_cast<int64_t>(static_cast<int16_t>(v & 0xFFFF)));
    case 4: return static_cast<uint64_t>(static_cast<int64_t>(static_cast<int32_t>(v & 0xFFFFFFFFull)));
    default: return v;
    }
}

struct Ctx {
    Emu& e;
    Loaded& l;
    Fetch& f;
    uint64_t instStart;
    int rexW = 0, rexR = 0, rexX = 0, rexB = 0;
    bool op66 = false, rexUsed = false;
    int segFs = 0;
    bool rep = false;
    uint32_t fault = fault_code(Fault::None);
    MR mr;
    Oprm o{};  // r/m operand after decodeRm
    Oprm g{};  // reg operand from modrm.reg
    bool oReg = false;
    bool ipSet = false;

    void castSet(int idx, int sz, uint64_t v) {
        if (sz == 4) { e.r[idx & 15] = v & 0xFFFFFFFFull; return; }
        if (sz == 2) { e.r[idx & 15] = (e.r[idx & 15] & ~0xFFFFull) | (v & 0xFFFF); return; }
        e.r[idx & 15] = v;
    }
    int operSz() const { return op66 ? 2 : 4; }

    uint32_t decodeRm() {
        if (fault != fault_code(Fault::None)) return fault;
        uint32_t r = decodeMR(f, mr);
        if (r != fault_code(Fault::None)) { fault = r; return r; }
        oReg = mr.mod == 3;
        o.isReg = oReg;
        const int idx = mr.rm | (rexB << 3);
        o.regIdx = idx;
        g.isReg = true;
        g.regIdx = mr.reg | (rexR << 3);
        return fault_code(Fault::None);
    }

    uint64_t eaCalc() {
        uint64_t ea = 0;
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
        return ea;
    }

    uint64_t oVal(int sz) {
        if (oReg) { o.addr = 0; return e.r[o.regIdx & 15] & maskSz(sz); }
        o.addr = eaCalc();
        if (sz == 8) { uint64_t v; if (!memLd(e, o.addr, v)) fault = fault_code(Fault::OutsideMemory); return v; }
        return oRead(e, o, sz, fault);
    }
    void oSet(int sz, uint64_t v) {
        if (oReg) {
            if (sz == 4) { e.r[o.regIdx & 15] = v & 0xFFFFFFFFull; return; }
            const uint64_t keep = ~maskSz(sz);
            e.r[o.regIdx & 15] = (e.r[o.regIdx & 15] & keep) | (v & maskSz(sz));
            return;
        }
        const uint64_t addr = eaCalc();
        o.addr = addr;
        oWrite(e, o, sz, v, fault);
    }
    uint64_t gVal(int sz) { return e.r[g.regIdx & 15] & maskSz(sz); }
    void gSet(int sz, uint64_t v) {
        if (sz == 4) { e.r[g.regIdx & 15] = v & 0xFFFFFFFFull; return; }
        const uint64_t keep = ~maskSz(sz);
        e.r[g.regIdx & 15] = (e.r[g.regIdx & 15] & keep) | (v & maskSz(sz));
    }

    uint64_t imm64(int sz, bool signImm8) {
        switch (sz) {
        case 1: { const uint8_t v = f.u8(); return signImm8 ? sext(1, v) : v; }
        case 2: { const uint16_t v = f.u16(); return v; }
        case 4: { const uint32_t v = f.u32(); return v; }
        case 8: { const uint32_t v = f.u32(); return signImm8 ? sext(4, v) : v; }
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
        if (oReg) return reg8Read(o.regIdx);
        o.addr = eaCalc();
        uint8_t v; if (!memLd(e, o.addr, v)) fault = fault_code(Fault::OutsideMemory);
        return v;
    }
    void o8Write(uint64_t v) {
        if (oReg) { reg8Write(o.regIdx, v); return; }
        const uint64_t addr = eaCalc();
        if (!memSt(e, addr, static_cast<uint8_t>(v))) fault = fault_code(Fault::OutsideMemory);
    }
    uint64_t g8Read() { return reg8Read(g.regIdx); }
    void g8Write(uint64_t v) { reg8Write(g.regIdx, v); }
};


inline void flagsNZP(Emu& e, int sz, uint64_t res) {
    res &= maskSz(sz);
    e.zf = res == 0;
    e.sf = (res & (1ull << (bitsSz(sz) - 1))) != 0;
    e.pf = (popcnt8(static_cast<uint8_t>(res & 0xFF)) % 2) == 0;
}
inline uint64_t adcOp(Emu& e, int sz, uint64_t a, uint64_t b, uint64_t cf) {
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
inline uint64_t sbbOp(Emu& e, int sz, uint64_t a, uint64_t b, uint64_t cf) {
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

uint32_t aluOp(Ctx& c, int fam, uint64_t a, uint64_t b, int sz, uint64_t& out) {
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

int64_t mulSigned(int sz, uint64_t a, uint64_t b, int& ovf) {
    ovf = 0;
    switch (sz) {
    case 1: { const int64_t v = static_cast<int64_t>(static_cast<int8_t>(a & 0xFF)) * static_cast<int64_t>(static_cast<int8_t>(b & 0xFF)); ovf = (v != static_cast<int64_t>(static_cast<int8_t>(v & 0xFF))); return v; }
    case 2: { const int64_t v = static_cast<int64_t>(static_cast<int16_t>(a & 0xFFFF)) * static_cast<int64_t>(static_cast<int16_t>(b & 0xFFFF)); ovf = (v != static_cast<int64_t>(static_cast<int16_t>(v & 0xFFFF))); return v; }
    case 4: { const int64_t v = static_cast<int64_t>(static_cast<int32_t>(a & 0xFFFFFFFFull)) * static_cast<int64_t>(static_cast<int32_t>(b & 0xFFFFFFFFull)); ovf = (v != static_cast<int64_t>(static_cast<int32_t>(v & 0xFFFFFFFFull))); return v; }
    default: ovf = -1; return 0;
    }
}

uint32_t step(Ctx& c);

uint32_t stepOne(Ctx& c) {
    Fetch& f = c.f;    for (;;) {
        const uint8_t p = f.data[f.pos];
        switch (p) {
        case 0x66: c.op66 = true; ++f.pos; continue;
        case 0x67: ++f.pos; continue;
        case 0x64: c.segFs = 1; ++f.pos; continue;
        case 0xF3: c.rep = true; ++f.pos; continue;
        case 0xF0: ++f.pos; continue; // lock: single-threaded, nothing to lock
        case 0x2E: case 0x3E: case 0x26: case 0x36: case 0x65:
            ++f.pos;
            continue;
        default:
            return step(c);
        }
    }
}

uint32_t step(Ctx& c) {
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
        const uint64_t imm = c.imm64(sz, false);
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
    case 0x60: { // pusha: AX,CX,DX,BX,orig SP,BP,SI,DI
        const uint32_t sp0 = static_cast<uint32_t>(c.e.r[4]);
        const uint32_t vals[8] = { static_cast<uint32_t>(c.e.r[0]), static_cast<uint32_t>(c.e.r[1]),
            static_cast<uint32_t>(c.e.r[2]), static_cast<uint32_t>(c.e.r[3]), sp0,
            static_cast<uint32_t>(c.e.r[5]), static_cast<uint32_t>(c.e.r[6]), static_cast<uint32_t>(c.e.r[7]) };
        for (int i = 0; i < 8; ++i)
            if (!memSt<uint32_t>(c.e, c.e.r[4] - 4, vals[i])) return fault_code(Fault::OutsideMemory);
        c.e.r[4] -= 32;
        return fault_code(Fault::None);
    }
    case 0x61: { // popa: DI,SI,BP,SPIP(skip),BX,DX,CX,AX from lowest address
        for (int i = 0; i < 8; ++i) {
            uint32_t v = 0;
            if (!memLd<uint32_t>(c.e, c.e.r[4], v)) return fault_code(Fault::OutsideMemory);
            c.e.r[4] += 4;
            const int idx = 7 - i;
            if (idx != 4) c.e.r[idx] = v;
        }
        return fault_code(Fault::None);
    }
    case 0x62: case 0x63: case 0x82:
        return fault_code(Fault::UnsupportedInstruction);
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
        const uint64_t a = c.oVal(sz);
        const uint64_t imm = (op == 0x69) ? c.imm64(sz, false) : sext(1, f.u8());
        if (c.fault != fault_code(Fault::None)) return c.fault;
        if (sz == 8) return fault_code(Fault::UnsupportedInstruction);
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
        const uint64_t nxt = c.l.img.base() + f.pos;
        c.ipSet = true;
        c.e.ip = cond(c.e, op & 0xF) ? nxt + static_cast<uint64_t>(rel) : nxt;
        return fault_code(Fault::None);
    }

    case 0x80: {
        if (c.op66) return fault_code(Fault::UnsupportedInstruction);
        c.decodeRm();
        if (c.fault != fault_code(Fault::None)) return c.fault;
        const int fam = c.mr.reg;
        const uint64_t a = c.o8Read();
        const uint8_t imm = f.u8();
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
        const uint64_t a = c.oVal(sz);
        if (c.fault != fault_code(Fault::None)) return c.fault;
        const uint64_t imm = (op == 0x83) ? sext(1, f.u8()) :
            (sz == 8 ? sext(4, f.u32()) : c.imm64(sz, false));
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
    case 0x8C: case 0x8E: case 0xD8: case 0xD9: case 0xDA: case 0xDB:
    case 0xDC: case 0xDD: case 0xDE: case 0xDF:
        return fault_code(Fault::UnsupportedInstruction);
    case 0x8D: {
        c.decodeRm();
        if (c.fault != fault_code(Fault::None)) return c.fault;
        if (c.oReg) return fault_code(Fault::UnsupportedInstruction);
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
    case 0x98: {
        if (c.op66) return fault_code(Fault::UnsupportedInstruction);
        if (c.rexW) { const uint64_t v = sext(4, c.e.r[0]); c.e.r[0] = v; }
        else { const uint64_t v = sext(2, c.e.r[0] & 0xFFFF); c.e.r[0] = (c.e.r[0] & ~0xFFFFFFFFull) | v; }
        return fault_code(Fault::None);
    }
    case 0x99: {
        if (c.op66) return fault_code(Fault::UnsupportedInstruction);
        if (c.rexW) c.e.r[2] = (c.e.r[0] & 0x8000000000000000ull) ? ~0ull : 0;
        else c.e.r[2] = (c.e.r[0] & 0x80000000ull) ? 0xFFFFFFFFull : 0;
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
    case 0xA0: case 0xA1: case 0xA2: case 0xA3: {
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
        return fault_code(Fault::None);
    }
    case 0xA6: case 0xA7: {
        const int sz = (op == 0xA6) ? 1 : (c.op66 ? 2 : 4);
        const int step = c.e.df ? -1 : 1;
        for (;;) {
            uint64_t si = c.e.r[6] & maskSz(4);
            uint64_t di = c.e.r[7] & maskSz(4);
            if (sz == 1) { uint8_t a, b; if (!memLd(c.e, si, a) || !memLd(c.e, di, b)) return fault_code(Fault::OutsideMemory); doSubF(c.e, 1, a, b); }
            else if (sz == 2) { uint16_t a, b; if (!memLd(c.e, si, a) || !memLd(c.e, di, b)) return fault_code(Fault::OutsideMemory); doSubF(c.e, 2, a, b); }
            else { uint32_t a, b; if (!memLd(c.e, si, a) || !memLd(c.e, di, b)) return fault_code(Fault::OutsideMemory); doSubF(c.e, 4, a, b); }
            c.e.r[6] = (si + step) & maskSz(4);
            c.e.r[7] = (di + step) & maskSz(4);
            if (!c.rep) break;
            --c.e.r[1];
            if (c.e.r[1] == 0 || !c.e.zf) break;
        }
        return fault_code(Fault::None);
    }
    case 0xA4: case 0xA5:
    case 0xAA: case 0xAB: case 0xAE: case 0xAF:
        return fault_code(Fault::UnsupportedInstruction);
    case 0xAC: case 0xAD: {
        const uint64_t si = c.e.r[6];
        if (op == 0xAC) {
            uint8_t v;
            if (!memLd(c.e, si, v)) { return fault_code(Fault::OutsideMemory); }
            c.reg8Write(0, v);
            c.e.r[6] = si + 1;
            return fault_code(Fault::None);
        }
        const int ls = c.op66 ? 2 : 4;
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
        const uint64_t imm = c.imm64(sz, false);
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
            if (kind == 0 || kind == 1 || kind == 2 || kind == 3) return fault_code(Fault::UnsupportedInstruction);
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
        c.ipSet = true;
        c.e.ip = v;
        c.e.r[4] += imm;
        return fault_code(Fault::None);
    }
    case 0xC3: {
        uint64_t v = 0;
        if (!pop64(c.e, v)) return fault_code(Fault::OutsideMemory);
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
    case 0xCA: case 0xCB: case 0xCC: case 0xCD: case 0xCE: case 0xCF:
    case 0xE4: case 0xE5: case 0xE6: case 0xE7:
    case 0xEE: case 0xEF: case 0xF1:
        return fault_code(Fault::UnsupportedInstruction);
    case 0xEB: {
        const int8_t rel = static_cast<int8_t>(f.u8());
        const uint64_t nxt = c.l.img.base() + f.pos;
        c.ipSet = true;
        c.e.ip = nxt + static_cast<uint64_t>(rel);
        return fault_code(Fault::None);
    }
    case 0xE8: {
        const uint32_t rel = f.u32();
        const uint64_t nxt = c.l.img.base() + f.pos + 0;
        if (!push64(c.e, nxt)) return fault_code(Fault::OutsideMemory);
        c.ipSet = true;
        c.e.ip = nxt + static_cast<uint64_t>(static_cast<int64_t>(static_cast<int32_t>(rel)));
        return fault_code(Fault::None);
    }
    case 0xE9: {
        const uint32_t rel = f.u32();
        const uint64_t nxt = c.l.img.base() + f.pos;
        c.ipSet = true;
        c.e.ip = nxt + static_cast<uint64_t>(static_cast<int64_t>(static_cast<int32_t>(rel)));
        return fault_code(Fault::None);
    }
    case 0xEA: case 0xEC: case 0xED:
        return fault_code(Fault::UnsupportedInstruction);
    case 0xE0: case 0xE1: case 0xE2: case 0xE3: {
        const int8_t rel = static_cast<int8_t>(f.u8());
        const uint64_t nxt = c.l.img.base() + f.pos;
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
    case 0xF4: return fault_code(Fault::Halt); // see run86: hlt ends the stub chain, exit = EAX
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
        const uint64_t a = c.o8Read();
        if (c.fault != fault_code(Fault::None)) return c.fault;
        switch (kind) {
        case 0: case 1: {
            const uint8_t imm = f.u8();
            doLogicOp(c.e, 1, a & imm);
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
        case 6: case 7: { // div / idiv: dividend AX, quotient AL, remainder AH
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
        default: return fault_code(Fault::UnsupportedInstruction);
        }
    }
    case 0xF7: {
        c.decodeRm();
        if (c.fault != fault_code(Fault::None)) return c.fault;
        const int kind = c.mr.reg;
        const uint64_t a = c.oVal(sz);
        if (c.fault != fault_code(Fault::None)) return c.fault;
        switch (kind) {
        case 0: case 1: {
            const uint64_t imm = (sz == 8) ? sext(4, f.u32()) : c.imm64(sz, false);
            doLogicOp(c.e, sz, a & imm);
            return fault_code(Fault::None);
        }
        case 2: c.oSet(sz, ~a & maskSz(sz)); if (c.fault != fault_code(Fault::None)) return c.fault; return fault_code(Fault::None);
        case 3: c.oSet(sz, doNegOp(c.e, sz, a)); if (c.fault != fault_code(Fault::None)) return c.fault; return fault_code(Fault::None);
        case 4: {
            if (sz == 8) return fault_code(Fault::UnsupportedInstruction);
            const uint64_t p = (c.e.r[0] & maskSz(sz)) * (a & maskSz(sz));
            c.e.r[0] = p & maskSz(sz);
            const uint64_t hi = (p >> bitsSz(sz)) & maskSz(sz);
            c.e.r[2] = hi;
            c.e.cf = c.e.of = (hi != 0);
            return fault_code(Fault::None);
        }
        case 5: {
            if (sz == 8) return fault_code(Fault::UnsupportedInstruction);
            int ovf = 0;
            const int64_t p = mulSigned(sz, c.e.r[0], a, ovf);
            (void)ovf;
            const uint64_t res = static_cast<uint64_t>(p) & maskSz(sz);
            c.e.r[0] = res;
            c.e.r[2] = (static_cast<uint64_t>(p) >> bitsSz(sz)) & maskSz(sz);
            c.e.cf = c.e.of = (static_cast<uint64_t>(p) != sext(sz, res));
            return fault_code(Fault::None);
        }
        case 6: case 7: { // div / idiv: dividend DX:AX (or EDX:EAX)
            if (sz == 8) return fault_code(Fault::UnsupportedInstruction);
            const bool unsignedDiv = (kind == 6);
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
        if (c.op66 && kind < 6) return fault_code(Fault::UnsupportedInstruction);
        if (kind == 0 || kind == 1) {
            const int osz = c.op66 ? 2 : 4;
            const uint64_t a = c.oVal(osz);
            if (c.fault != fault_code(Fault::None)) return c.fault;
            if (kind == 0) c.oSet(osz, doIncOp(c.e, osz, a)); else c.oSet(osz, doDecOp(c.e, osz, a));
            if (c.fault != fault_code(Fault::None)) return c.fault;
            return fault_code(Fault::None);
        }
        if (kind == 2 || kind == 4) {
            const uint64_t a = c.oVal(c.op66 ? 2 : 4);
            if (c.fault != fault_code(Fault::None)) return c.fault;
            const uint64_t nxt = c.l.img.base() + f.pos;
            if (kind == 2) { if (!push64(c.e, nxt)) return fault_code(Fault::OutsideMemory); }
            c.ipSet = true;
            c.e.ip = a;
            return fault_code(Fault::None);
        }
        if (kind == 6) {
            const uint64_t a = c.oVal(c.op66 ? 2 : 4);
            if (c.fault != fault_code(Fault::None)) return c.fault;
            return push64(c.e, a) ? fault_code(Fault::None) : fault_code(Fault::OutsideMemory);
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
        case 0xA2: { // CPUID: Intel vendor; leaves past 1 report no features so
                     // the CRT runtime dispatch settles on plain SSE2
            const uint64_t leaf = c.e.r[2] & 0xFFFFFFFF;
            if (leaf == 0)
                c.e.r[0] = 1, c.e.r[3] = 0x756E6547,
                c.e.r[1] = 0x49656E69, c.e.r[2] = 0x6C65746E;
            else if (leaf == 1)
                c.e.r[0] = 0x633, c.e.r[3] = 1u << 26, c.e.r[2] = 0, c.e.r[1] = 0;
            else
                c.e.r[0] = c.e.r[1] = c.e.r[2] = c.e.r[3] = 0;
            return fault_code(Fault::None);
        }
        case 0x57: { // xorps dst, src: only the reg,reg zero idiom appears here
            c.decodeRm();
            if (c.fault != fault_code(Fault::None)) return c.fault;
            if (!c.oReg) return fault_code(Fault::UnsupportedInstruction);
            const int dst = c.mr.reg, src = c.mr.rm;
            c.e.xmm[dst][0] = c.e.xmm[dst][1] = c.e.xmm[dst][0] ^ c.e.xmm[src][0];
            c.e.xmm[dst][1] ^= c.e.xmm[src][1];
            return fault_code(Fault::None);
        }
        case 0x12: case 0x13: { // 66 movlpd xmm, m64 / movlpd m64, xmm
            if (!c.op66) return fault_code(Fault::UnsupportedInstruction);
            c.decodeRm();
            if (c.fault != fault_code(Fault::None)) return c.fault;
            if (c.oReg) return fault_code(Fault::UnsupportedInstruction);
            const int reg = c.mr.reg;
            const uint64_t ea = c.eaCalc();
            if (op2 == 0x13) {
                if (!memSt(c.e, ea, c.e.xmm[reg][0])) c.fault = fault_code(Fault::OutsideMemory);
            } else {
                if (!memLd(c.e, ea, c.e.xmm[reg][0])) c.fault = fault_code(Fault::OutsideMemory);
                c.e.xmm[reg][1] = 0;
            }
            if (c.fault != fault_code(Fault::None)) return c.fault;
            return fault_code(Fault::None);
        }
        case 0x0B: return fault_code(Fault::UnsupportedInstruction);
        case 0x05: case 0x34: case 0x35:
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
            const uint64_t nxt = c.l.img.base() + f.pos;
            c.ipSet = true;
            c.e.ip = cond(c.e, op2 & 0xF) ? nxt + rel : nxt;
            return fault_code(Fault::None);
        }
        case 0x90: case 0x91: case 0x92: case 0x93: case 0x94: case 0x95: case 0x96: case 0x97:
        case 0x98: case 0x99: case 0x9A: case 0x9B: case 0x9C: case 0x9D: case 0x9E: case 0x9F: {
            c.decodeRm();
            if (c.fault != fault_code(Fault::None)) return c.fault;
            const uint64_t v = cond(c.e, op2 & 0xF) ? 1 : 0;
            if (c.oReg) { const int idx = (c.mr.rm | (c.rexB << 3)) & 15; c.reg8Write(idx, v); }
            else { const uint64_t addr = c.eaCalc(); if (!memSt(c.e, addr, static_cast<uint8_t>(v))) c.fault = fault_code(Fault::OutsideMemory); }
            if (c.fault != fault_code(Fault::None)) return c.fault;
            return fault_code(Fault::None);
        }
        case 0xB0: case 0xB1: { // cmpxchg r/m, r: single-threaded, lock prefix is a no-op
            const int osz = (op2 == 0xB1) ? (c.op66 ? 2 : 4) : 1;
            c.decodeRm();
            if (c.fault != fault_code(Fault::None)) return c.fault;
            const uint64_t dst = c.oVal(osz);
            if (c.fault != fault_code(Fault::None)) return c.fault;
            const uint64_t src = c.gVal(osz);
            const uint64_t acc = c.e.r[0] & maskSz(osz);
            // flags match x86: ZF means exchange happened
            c.e.zf = dst == acc;
            if (c.e.zf) {
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
            if (sz == 8) return fault_code(Fault::UnsupportedInstruction);
            int ovf = 0;
            const int64_t prod = mulSigned(sz, c.gVal(sz), a, ovf);
            const uint64_t res = static_cast<uint64_t>(prod) & maskSz(sz);
            c.e.cf = c.e.of = ovf != 0;
            c.gSet(sz, res);
            if (c.fault != fault_code(Fault::None)) return c.fault;
            return fault_code(Fault::None);
        }
        case 0xB6: case 0xB7: {
            c.decodeRm();
            if (c.fault != fault_code(Fault::None)) return c.fault;
            const uint64_t v = c.oVal(op2 == 0xB6 ? 1 : 2);
            if (c.fault != fault_code(Fault::None)) return c.fault;
            c.gSet(c.op66 ? 2 : 4, v);
            if (c.fault != fault_code(Fault::None)) return c.fault;
            return fault_code(Fault::None);
        }
        case 0xBE: case 0xBF: {
            c.decodeRm();
            if (c.fault != fault_code(Fault::None)) return c.fault;
            const int from = (op2 == 0xBE) ? 1 : 2;
            const uint64_t v = c.oVal(from);
            if (c.fault != fault_code(Fault::None)) return c.fault;
            c.gSet(c.op66 ? 2 : 4, sext(from, v));
            if (c.fault != fault_code(Fault::None)) return c.fault;
            return fault_code(Fault::None);
        }
        case 0xC8: case 0xC9: case 0xCA: case 0xCB: case 0xCC: case 0xCD: case 0xCE: case 0xCF: {
            const int idx = (op2 & 7) | (c.rexB << 3);
            if (c.rexW) {
                uint64_t v = c.e.r[idx & 15];
                c.e.r[idx & 15] = _byteswap_uint64(v);
            } else {
                const uint64_t v = c.e.r[idx & 15] & 0xFFFFFFFFull;
                c.e.r[idx & 15] = _byteswap_ulong(static_cast<unsigned long>(v));
            }
            return fault_code(Fault::None);
        }
        default:
            return fault_code(Fault::UnsupportedInstruction);
        }
    }

    case 0x40: case 0x41: case 0x42: case 0x43: case 0x44: case 0x45: case 0x46: case 0x47: {
        const int osz = c.op66 ? 2 : 4;
        const int idx = op & 7;
        c.e.r[idx & 15] = doIncOp(c.e, osz, c.e.r[idx & 15]);
        return fault_code(Fault::None);
    }
    case 0x48: case 0x49: case 0x4A: case 0x4B: case 0x4C: case 0x4D: case 0x4E: case 0x4F: {
        const int osz = c.op66 ? 2 : 4;
        const int idx = op & 7;
        c.e.r[idx & 15] = doDecOp(c.e, osz, c.e.r[idx & 15]);
        return fault_code(Fault::None);
    }

    default:
        return fault_code(Fault::UnsupportedInstruction);
    }
}

static uint32_t runLoop(Emu& e) {
    Loaded& l = *e.l;
    const uint64_t sentinel32 = kSentinel & 0xFFFFFFFFull;
    for (;;) {
        if (e.ip == sentinel32) break;
        if (const ApiEntry* api = l.apis.find(e.ip)) {
            // compiled-in stand-in: stdcall, callee pops ret + args
            uint64_t args[8] = { 0, 0, 0, 0, 0, 0, 0, 0 };
            for (int i = 0; i < api->nargs && i < 8; ++i) {
                uint32_t a = 0;
                if (!memLd<uint32_t>(e, e.r[4] + 4 + 4 * i, a)) return fault_code(Fault::OutsideMemory);
                args[i] = a;
            }
            uint32_t ret = 0;
            if (!memLd<uint32_t>(e, e.r[4], ret)) return fault_code(Fault::OutsideMemory);
            e.r[4] += api->callerCleans ? 4 : 4 * (1 + api->nargs);
            e.r[0] = static_cast<uint32_t>(api->fn(l, args));
            if (l.fault != fault_code(Fault::None)) return l.fault;
            e.ip = ret;
            continue;
        }
        if (e.budget == 0) return fault_code(Fault::Budget);
        --e.budget;
        if (e.ip < l.img.base() || e.ip >= e.imgEnd) {
            fprintf(stderr, "instruction fetch outside image: ip=0x%llX\n",
                    static_cast<unsigned long long>(e.ip));
            return fault_code(Fault::OutsideMemory);
        }
        Fetch f{l.img.data(), l.img.size(), static_cast<size_t>(e.ip - l.img.base())};
        Ctx c{e, l, f, e.ip};
        const uint32_t r = stepOne(c);
        if (r != fault_code(Fault::None)) {
            if (r == fault_code(Fault::Halt)) break; // stub chain end: exit code = EAX (run86)
            if (r == fault_code(Fault::OutsideMemory)) {
                fprintf(stderr, "fault: access outside emulated memory at ip=0x%llX (off=0x%llX)\n",
                        static_cast<unsigned long long>(e.ip),
                        static_cast<unsigned long long>(e.ip - l.img.base()));
            }
            return r;
        }
        if (!c.ipSet) {
            e.ip = c.l.img.base() + f.pos;
        }
    }
    return fault_code(Fault::None);
}

uint32_t run86(Loaded& l) {
    Emu e;
    e.l = &l;
    e.imgEnd = l.img.base() + l.img.size();
    e.stkEnd = l.stk.base() + l.stk.size();
    e.fsBase = l.fsBase;
    e.envBase = l.env.base();
    e.envEnd = l.env.base() + l.env.size();

    // leave 0x100 bytes above the initial esp: stand-in interception may peek
    // at unused vararg slots, and reads must stay inside the region
    e.r[kRSP] = e.stkEnd - 4 - 0x100;
    if (!memSt<uint32_t>(e, e.r[kRSP], static_cast<uint32_t>(kSentinel))) return fault_code(Fault::OutsideMemory);
    e.ip = l.img.base();
    if (l.pe.is_dll) {
        // DLL entry signature: _DllMainCRTStartup is stdcall ret 12, args
        // above the return address: hinst, DLL_PROCESS_ATTACH, nullptr
        const uint32_t hinst = static_cast<uint32_t>(l.img.base() + l.pe.image_offset);
        if (!memSt<uint32_t>(e, e.r[kRSP] + 4, hinst) ||
            !memSt<uint32_t>(e, e.r[kRSP] + 8, 1) ||
            !memSt<uint32_t>(e, e.r[kRSP] + 12, 0)) return fault_code(Fault::OutsideMemory);
    }

    const uint32_t r = runLoop(e);
    if (r != fault_code(Fault::None) && r != fault_code(Fault::Halt)) return r;
    return static_cast<uint32_t>(e.r[0] & 0xFFFFFFFFull);
}

uint32_t runThread86(Loaded& l, ThreadCtx& t) {
    Emu e;
    e.l = &l;
    e.imgEnd = l.img.base() + l.img.size();
    e.stkEnd = t.stack.base() + t.stack.size();
    e.fsBase = l.fsBase;
    e.envBase = l.env.base();
    e.envEnd = l.env.base() + l.env.size();

    // entry state of a real thread start (__stdcall): [esp] return address,
    // [esp+4] thread argument
    e.r[kRSP] = e.stkEnd - 4 - 0x100;
    if (!memSt<uint32_t>(e, e.r[kRSP], static_cast<uint32_t>(kSentinel))) return fault_code(Fault::OutsideMemory);
    if (!memSt<uint32_t>(e, e.r[kRSP] + 4, static_cast<uint32_t>(t.arg))) return fault_code(Fault::OutsideMemory);
    e.ip = t.entry;

    const uint32_t r = runLoop(e);
    if (r != fault_code(Fault::None)) return r;
    return static_cast<uint32_t>(e.r[0] & 0xFFFFFFFFull);
}

} // namespace x86

uint32_t run86(Loaded& l) {
    return x86::run86(l);
}

uint32_t runThread86(Loaded& l, ThreadCtx& t) {
    return x86::runThread86(l, t);
}

} // namespace stub
