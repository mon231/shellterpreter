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

uint32_t loadShellcode(const std::string& path, Loaded& out, bool force86) {
    ShellcodeFile file;
    if (!file.open(path)) return fault_code(Fault::BadFile);
    const std::vector<uint8_t>& data = file.bytes();

    PeReader pe_reader;
    const bool hasImage = pe_reader.scan(data);
    const uint16_t machine = pe_reader.machine();

    // below4: the x86 core addresses guest regions through 32-bit pointers,
    // so every region must land under 4 GiB when an x86 guest runs.
    const bool below4 = !out.is64;
    if (!out.img.allocate(data.size() + 0x10000, below4))
        return fault_code(Fault::Allocation);
    memcpy(out.img.data(), data.data(), data.size());
    out.pe = pe_reader.info();
    out.hasImage = hasImage;
    out.is64 = hasImage ? (machine == 0x8664) : !force86;

    const uint64_t stack_size = 4 * 1024 * 1024;
    if (!out.stk.allocate(stack_size, below4))
        return fault_code(Fault::Allocation);

    // env/heap: GuestRegion members free themselves on any early return
    return buildFakeEnv(out);
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
    uint32_t err = stub::loadShellcode(path, l, arch == 32);
    if (err != fault_code(Fault::None)) { printFault(err); return static_cast<int>(err); }

    if (!l.hasImage) {
        if (arch == 0) { printFault(fault_code(Fault::Argument)); return fault_code(Fault::Argument); }
        l.is64 = (arch == 64);
    }
    if (l.hasImage) {
        if (arch == 32 && l.is64) { printFault(fault_code(Fault::Architecture)); return fault_code(Fault::Architecture); }
        if (arch == 64 && !l.is64) { printFault(fault_code(Fault::Architecture)); return fault_code(Fault::Architecture); }
    }

#ifndef _WIN64
    // 32-bit host build runs x86 shellcode only
    if (l.is64) { printFault(fault_code(Fault::Architecture)); return fault_code(Fault::Architecture); }
#endif

    std::vector<stub::ExecRange> baseline = stub::snapshotExecRanges();

    uint32_t result = fault_code(Fault::None);
    if (l.is64) result = stub::run64(l);
    else result = stub::run86(l);

    bool ok = true;
    if (stub::pageHasExecute(l.img.base()) || stub::pageHasExecute(l.stk.base()) ||
        stub::pageIsWriteAndExec(l.img.base()) || stub::pageIsWriteAndExec(l.stk.base())) {
        ok = false;
        result = fault_code(Fault::Audit);
    }
    if (ok && !stub::verifyNoNewExec(baseline)) { ok = false; result = fault_code(Fault::Audit); }
    if (result >= 0xE0000000u) { printFault(result); }
    return static_cast<int>(result);
}
