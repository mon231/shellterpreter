#include "vm.hpp"
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cstdio>
#include <cstring>

namespace stub {
namespace x64 {

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
    uint64_t budget = kInstrBudget;
};

constexpr uint64_t kWmask[5] = { 0, 0xFF, 0xFFFF, 0xFFFFFFFFull, ~0ull };
constexpr unsigned kWbits[5] = { 0, 8, 16, 32, 64 };
inline uint64_t maskSz(int sz) { return kWmask[sz]; }
inline unsigned bitsSz(int sz) { return kWbits[sz]; }

inline void flagsLogic(Emu& e, int sz, uint64_t res) {
    e.cf = e.of = false;
    res &= maskSz(sz);
    e.zf = res == 0;
    e.sf = (res & (1ull << (bitsSz(sz) - 1))) != 0;
    e.pf = (__popcnt64(res & 0xFF) % 2) == 0;
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
inline uint64_t doSubF(Emu& e, int sz, uint64_t a, uint64_t b) {
    const uint64_t aa = a & maskSz(sz), bb = b & maskSz(sz);
    const uint64_t res = (aa - bb) & maskSz(sz);
    e.cf = aa < bb;
    const uint64_t sign = 1ull << (bitsSz(sz) - 1);
    e.of = (((aa ^ bb) & (aa ^ res)) & sign) != 0;
    e.af = ((aa ^ bb ^ res) & 0x10) != 0;
    flagsLogic(e, sz, res);
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
    if (addr >= e.l->imgBase && addr + sizeof(T) <= e.imgEnd)
        return e.l->img + (addr - e.l->imgBase);
    if (addr >= e.l->stkBase && addr + sizeof(T) <= e.stkEnd)
        return e.l->stk + (addr - e.l->stkBase);
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
    const uint64_t addr = e.r[kRSP] - 8;
    if (!memSt<uint64_t>(e, addr, v)) return false;
    e.r[kRSP] = addr;
    return true;
}
inline bool pop64(Emu& e, uint64_t& v) {
    if (!memLd<uint64_t>(e, e.r[kRSP], v)) return false;
    e.r[kRSP] += 8;
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
    bool ripRel = false;
};

uint32_t decodeMR(Fetch& f, MR& m) {
    const uint8_t byte = f.u8();
    m.mod = byte >> 6;
    m.reg = (byte >> 3) & 7;
    m.rm = byte & 7;
    m.hasSib = false;
    m.ripRel = false;
    m.disp = 0;
    if (m.mod == 3) return FAULT_NONE;
    if (m.rm == 4) {
        m.hasSib = true;
        const uint8_t sib = f.u8();
        m.sibScale = sib >> 6;
        m.sibIndex = (sib >> 3) & 7;
        m.sibBase = sib & 7;
        if (m.sibBase == 5 && m.mod == 0) { m.disp = static_cast<int32_t>(f.u32()); return FAULT_NONE; }
        if (m.mod == 1) m.disp = static_cast<int8_t>(f.u8());
        else if (m.mod == 2) m.disp = static_cast<int32_t>(f.u32());
        return FAULT_NONE;
    }
    if (m.rm == 5 && m.mod == 0) { m.ripRel = true; m.disp = static_cast<int32_t>(f.u32()); return FAULT_NONE; }
    if (m.mod == 1) m.disp = static_cast<int8_t>(f.u8());
    else if (m.mod == 2) m.disp = static_cast<int32_t>(f.u32());
    return FAULT_NONE;
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
    case 1: { uint8_t v; if (!memLd(e, o.addr, v)) { fault = FAULT_OOB; return 0; } return v; }
    case 2: { uint16_t v; if (!memLd(e, o.addr, v)) { fault = FAULT_OOB; return 0; } return v; }
    case 4: { uint32_t v; if (!memLd(e, o.addr, v)) { fault = FAULT_OOB; return 0; } return v; }
    case 8: { uint64_t v; if (!memLd(e, o.addr, v)) { fault = FAULT_OOB; return 0; } return v; }
    }
    fault = FAULT_UNSUPPORTED; return 0;
}
void oWrite(Emu& e, const Oprm& o, int sz, uint64_t v, uint32_t& fault) {
    if (o.isReg) {
        if (sz == 4) { e.r[o.regIdx & 15] = v & 0xFFFFFFFFull; return; }
        const uint64_t keep = ~maskSz(sz);
        e.r[o.regIdx & 15] = (e.r[o.regIdx & 15] & keep) | (v & maskSz(sz));
        return;
    }
    switch (sz) {
    case 1: if (!memSt(e, o.addr, static_cast<uint8_t>(v))) fault = FAULT_OOB; break;
    case 2: if (!memSt(e, o.addr, static_cast<uint16_t>(v))) fault = FAULT_OOB; break;
    case 4: if (!memSt(e, o.addr, static_cast<uint32_t>(v))) fault = FAULT_OOB; break;
    case 8: if (!memSt(e, o.addr, v)) fault = FAULT_OOB; break;
    default: fault = FAULT_UNSUPPORTED; break;
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
    uint32_t fault = FAULT_NONE;
    MR mr;
    Oprm o{};  // r/m operand after decodeRm
    Oprm g{};  // reg operand from modrm.reg
    bool oReg = false;

    int operSz() const { return op66 ? 2 : (rexW ? 8 : 4); }

    uint32_t decodeRm() {
        if (fault != FAULT_NONE) return fault;
        uint32_t r = decodeMR(f, mr);
        if (r != FAULT_NONE) { fault = r; return r; }
        oReg = mr.mod == 3;
        o.isReg = oReg;
        const int idx = mr.rm | (rexB << 3);
        o.regIdx = idx;
        g.isReg = true;
        g.regIdx = mr.reg | (rexR << 3);
        return FAULT_NONE;
    }

    uint64_t eaCalc() {
        uint64_t ea = 0;
        if (mr.ripRel) {
            ea = instStart + f.pos + mr.disp;
        } else if (mr.hasSib) {
            ea = 0;
            if (!(mr.sibBase == 5 && mr.mod == 0)) ea += e.r[mr.sibBase | (rexB << 3)];
            if (mr.sibIndex != 4) ea += e.r[mr.sibIndex | (rexX << 3)] << mr.sibScale;
            ea += mr.disp;
        } else {
            ea = e.r[mr.rm | (rexB << 3)] + mr.disp;
        }
        return ea;
    }

    uint64_t oVal(int sz) {
        if (oReg) { o.addr = 0; return e.r[o.regIdx & 15] & maskSz(sz); }
        o.addr = eaCalc();
        if (sz == 8) { uint64_t v; if (!memLd(e, o.addr, v)) fault = FAULT_OOB; return v; }
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
        fault = FAULT_UNSUPPORTED; return 0;
    }
};

