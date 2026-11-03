#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include "vm.hpp"
#include "audit.hpp"
#include "export_resolver.hpp"
#include "shellcode_file.hpp"
#include "pe_reader.hpp"

namespace stub {

void freeLoaded(Loaded& l) {
    if (l.img) { VirtualFree(l.img, 0, MEM_RELEASE); l.img = nullptr; }
    if (l.stk) { VirtualFree(l.stk, 0, MEM_RELEASE); l.stk = nullptr; }
    if (l.env) { VirtualFree(l.env, 0, MEM_RELEASE); l.env = nullptr; }
    if (l.heap) { VirtualFree(l.heap, 0, MEM_RELEASE); l.heap = nullptr; }
    for (uint32_t i = 0; i < l.threadCount; ++i)
        if (l.threads[i].stack) { VirtualFree(l.threads[i].stack, 0, MEM_RELEASE); l.threads[i].stack = nullptr; }
}

uint32_t loadShellcode(const std::string& path, Loaded& out, bool force86) {
    ShellcodeFile file;
    if (!file.open(path)) return fault_code(Fault::BadFile);
    const std::vector<uint8_t>& data = file.bytes();

    PeReader pe_reader;
    const bool hasImage = pe_reader.scan(data);
    const uint16_t machine = pe_reader.machine();

    const bool low = !out.is64;
    const size_t want = data.size() + 0x10000;
    void* buf = low ? allocLow(want) : VirtualAlloc(nullptr, want, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!buf) return fault_code(Fault::Allocation);
    uint8_t* base = static_cast<uint8_t*>(buf);
    memcpy(base, data.data(), data.size());

    out.img = base;
    out.imgLen = want;
    out.imgBase = reinterpret_cast<uint64_t>(base);
    out.pe = pe_reader.info();
    out.hasImage = hasImage;
    out.is64 = hasImage ? (machine == 0x8664) : !force86;

    const size_t kStack = 4 * 1024 * 1024;
    void* stk = low ? allocLow(kStack) : VirtualAlloc(nullptr, kStack, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!stk) { VirtualFree(buf, 0, MEM_RELEASE); return fault_code(Fault::Allocation); }
    out.stk = static_cast<uint8_t*>(stk);
    out.stkLen = kStack;
    out.stkBase = reinterpret_cast<uint64_t>(stk);

    const uint32_t err = buildFakeEnv(out);
    if (err != fault_code(Fault::None)) { freeLoaded(out); return err; }
    return fault_code(Fault::None);
}

} // namespace stub

static void printFault(uint32_t code) {
    fprintf(stderr, "shellterpreter: fault 0x%08X (%s)\n",
            code, fault_message(code).c_str());
}

int main(int argc, char** argv) {
    std::string path;
    int arch = 0;
    for (int i = 1; i < argc; ++i) {
        const std::string a = argv[i];
        if (a == "--x86") arch = 32;
        else if (a == "--x64") arch = 64;
        else if (!a.empty() && a[0] != '-') { if (path.empty()) path = a; }
        else { printFault(fault_code(Fault::Argument)); return fault_code(Fault::Argument); }
    }
    if (path.empty()) {
        fprintf(stderr, "usage: shellterpreter.exe <shellcode.bin> [--x86|--x64]\n");
        return fault_code(Fault::Argument);
    }

    stub::Loaded l{};
    l.img = l.stk = nullptr;
    l.is64 = l.hasImage = false;
    uint32_t err = stub::loadShellcode(path, l, arch == 32);
    if (err != fault_code(Fault::None)) { printFault(err); return static_cast<int>(err); }

    if (!l.hasImage) {
        if (arch == 0) { printFault(fault_code(Fault::Argument)); stub::freeLoaded(l); return fault_code(Fault::Argument); }
        l.is64 = (arch == 64);
    }
    if (l.hasImage) {
        if (arch == 32 && l.is64) { printFault(fault_code(Fault::Architecture)); stub::freeLoaded(l); return fault_code(Fault::Architecture); }
        if (arch == 64 && !l.is64) { printFault(fault_code(Fault::Architecture)); stub::freeLoaded(l); return fault_code(Fault::Architecture); }
    }

#ifndef _WIN64
    // 32-bit host build runs x86 shellcode only
    if (l.is64) { printFault(fault_code(Fault::Architecture)); stub::freeLoaded(l); return fault_code(Fault::Architecture); }
#endif

    std::vector<stub::ExecRange> baseline = stub::snapshotExecRanges();

    uint32_t result = fault_code(Fault::None);
    if (l.is64) result = stub::run64(l);
    else result = stub::run86(l);

    bool ok = true;
    if (stub::pageHasExecute(l.imgBase) || stub::pageHasExecute(l.stkBase) ||
        stub::pageIsWriteAndExec(l.imgBase) || stub::pageIsWriteAndExec(l.stkBase)) {
        ok = false;
        result = fault_code(Fault::Audit);
    }
    if (ok && !stub::verifyNoNewExec(baseline)) { ok = false; result = fault_code(Fault::Audit); }
    stub::freeLoaded(l);
    if (result >= 0xE0000000u) { printFault(result); }
    return static_cast<int>(result);
}
