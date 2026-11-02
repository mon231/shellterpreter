#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include "vm.hpp"
#include "audit.hpp"
#include "export_resolver.hpp"

namespace stub {

void freeLoaded(Loaded& l) {
    if (l.img) { VirtualFree(l.img, 0, MEM_RELEASE); l.img = nullptr; }
    if (l.stk) { VirtualFree(l.stk, 0, MEM_RELEASE); l.stk = nullptr; }
    if (l.env) { VirtualFree(l.env, 0, MEM_RELEASE); l.env = nullptr; }
}

std::string faultMessage(uint32_t fault) {
    switch (fault) {
    case FAULT_UNSUPPORTED: return "unimplemented opcode";
    case FAULT_OOB:         return "access outside emulated memory";
    case FAULT_BAD_FILE:    return "bad shellcode file";
    case FAULT_ALLOC:       return "memory allocation failed";
    case FAULT_AUDIT:       return "runtime self-audit violated";
    case FAULT_HALT:        return "hlt executed";
    case FAULT_ARCH:        return "architecture mismatch or core not built";
    case FAULT_ARG:         return "bad command line";
    case FAULT_LIMIT:       return "instruction budget exhausted";
    default:                return "unknown state";
    }
}

uint32_t loadShellcode(const std::string& path, Loaded& out, bool force86) {
    HANDLE h = CreateFileA(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return FAULT_BAD_FILE;
    DWORD hi = 0;
    const DWORD lo = GetFileSize(h, &hi);
    if (lo == INVALID_FILE_SIZE && hi != 0) { CloseHandle(h); return FAULT_BAD_FILE; }
    std::vector<uint8_t> data;
    data.resize(static_cast<size_t>((static_cast<uint64_t>(hi) << 32) | lo));
    DWORD got = 0;
    if (!ReadFile(h, data.data(), static_cast<DWORD>(data.size()), &got, nullptr) ||
        got != data.size() || data.empty()) {
        CloseHandle(h);
        return FAULT_BAD_FILE;
    }
    CloseHandle(h);

    uint64_t imgOff = 0;
    uint16_t machine = 0;
    bool hasImage = false;
    for (size_t s = 0; s + 2 < data.size() && s < 0x10000; ++s) {
        if (data[s] != 'M' || data[s + 1] != 'Z') continue;
        if (s + 0x40 > data.size()) continue;
        const uint32_t eLfanew = *reinterpret_cast<const uint32_t*>(&data[s + 0x3C]);
        if (eLfanew > 0x1000) continue;
        const size_t peOff = s + eLfanew;
        if (peOff + 6 > data.size()) continue;
        const uint8_t* pk = &data[peOff];
        if (!(pk[0] == 'P' && pk[1] == 'E' && pk[2] == 0 && pk[3] == 0)) continue;
        machine = static_cast<uint16_t>(pk[4] | (pk[5] << 8));
        imgOff = s;
        hasImage = true;
        break;
    }

    const bool low = !out.is64;
    const size_t want = data.size() + 0x10000;
    void* buf = low ? allocLow(want) : VirtualAlloc(nullptr, want, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!buf) return FAULT_ALLOC;
    uint8_t* base = static_cast<uint8_t*>(buf);
    memcpy(base, data.data(), data.size());

    out.img = base;
    out.imgLen = want;
    out.imgBase = reinterpret_cast<uint64_t>(base);
    out.pe.imageOffset = imgOff;
    out.hasImage = hasImage;
    out.is64 = hasImage ? (machine == 0x8664) : !force86;

    if (hasImage) {
        const uint32_t eLfanew = *reinterpret_cast<const uint32_t*>(base + imgOff + 0x3C);
        const uint8_t* opt = base + imgOff + eLfanew + 4 + 20;
        out.pe.entryRva = *reinterpret_cast<const uint32_t*>(opt + 16);
        if (out.is64) {
            out.pe.imageBase = static_cast<uint32_t>(*reinterpret_cast<const uint64_t*>(opt + 24));
            out.pe.sizeOfImage = *reinterpret_cast<const uint32_t*>(opt + 56);
        } else {
            out.pe.imageBase = *reinterpret_cast<const uint32_t*>(opt + 28);
            out.pe.sizeOfImage = *reinterpret_cast<const uint32_t*>(opt + 56);
        }
    }

    const size_t kStack = 4 * 1024 * 1024;
    void* stk = low ? allocLow(kStack) : VirtualAlloc(nullptr, kStack, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!stk) { VirtualFree(buf, 0, MEM_RELEASE); return FAULT_ALLOC; }
    out.stk = static_cast<uint8_t*>(stk);
    out.stkLen = kStack;
    out.stkBase = reinterpret_cast<uint64_t>(stk);

    const uint32_t err = buildFakeEnv(out);
    if (err != FAULT_NONE) { freeLoaded(out); return err; }
    return FAULT_NONE;
}

} // namespace stub

static void printFault(uint32_t code) {
    fprintf(stderr, "shellterpreter: fault 0x%08X (%s)\n",
            code, stub::faultMessage(code).c_str());
}

int main(int argc, char** argv) {
    std::string path;
    int arch = 0;
    for (int i = 1; i < argc; ++i) {
        const std::string a = argv[i];
        if (a == "--x86") arch = 32;
        else if (a == "--x64") arch = 64;
        else if (!a.empty() && a[0] != '-') { if (path.empty()) path = a; }
        else { printFault(stub::FAULT_ARG); return stub::FAULT_ARG; }
    }
    if (path.empty()) {
        fprintf(stderr, "usage: shellterpreter.exe <shellcode.bin> [--x86|--x64]\n");
        return stub::FAULT_ARG;
    }

    stub::Loaded l{};
    l.img = l.stk = nullptr;
    l.is64 = l.hasImage = false;
    uint32_t err = stub::loadShellcode(path, l, arch == 32);
    if (err != stub::FAULT_NONE) { printFault(err); return static_cast<int>(err); }

    if (!l.hasImage) {
        if (arch == 0) { printFault(stub::FAULT_ARG); stub::freeLoaded(l); return stub::FAULT_ARG; }
        l.is64 = (arch == 64);
    }
    if (l.hasImage) {
        if (arch == 32 && l.is64) { printFault(stub::FAULT_ARCH); stub::freeLoaded(l); return stub::FAULT_ARCH; }
        if (arch == 64 && !l.is64) { printFault(stub::FAULT_ARCH); stub::freeLoaded(l); return stub::FAULT_ARCH; }
    }

    std::vector<stub::ExecRange> baseline = stub::snapshotExecRanges();

    uint32_t result = stub::FAULT_NONE;
    if (l.is64) result = stub::run64(l);
    else result = stub::run86(l);

    bool ok = true;
    if (stub::pageHasExecute(l.imgBase) || stub::pageHasExecute(l.stkBase) ||
        stub::pageIsWriteAndExec(l.imgBase) || stub::pageIsWriteAndExec(l.stkBase)) {
        ok = false;
        result = stub::FAULT_AUDIT;
    }
    if (ok && !stub::verifyNoNewExec(baseline)) { ok = false; result = stub::FAULT_AUDIT; }
    stub::freeLoaded(l);
    if (result >= 0xE0000000u) { printFault(result); }
    return static_cast<int>(result);
}
