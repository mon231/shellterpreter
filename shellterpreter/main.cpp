#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include "vm.hpp"
#include "audit.hpp"
#include "guest_environment.hpp"
#include "api_standins.hpp"
#include "shellcode_file.hpp"

namespace stub {

uint32_t loadShellcode(const std::string& path, Loaded& out, bool force86) {
    ShellcodeFile file;
    if (!file.open(path)) return fault_code(Fault::BadFile);
    const std::vector<uint8_t>& data = file.bytes();

    // The blob is opaque bytes: no header scan, no format assumptions. It is
    // mapped verbatim, execution starts at offset 0 and the architecture is
    // whatever the caller asked for. A shellcode that needs image-relative
    // services (x64 table EH, resources) declares its layout itself by
    // writing the descriptor globals in the fake environment.
    out.is64 = !force86;

    // below4 always: the x86 core addresses guest regions through 32-bit
    // pointers, and the stand-ins truncate guest pointers to 32 bits, so
    // every region must land under 4 GiB in every configuration.
    const bool below4 = true;
    if (!out.img.allocate(data.size() + 0x10000, below4))
        return fault_code(Fault::Allocation);
    memcpy(out.img.data(), data.data(), data.size());

    // filename stem: what the stand-ins report as the guest's own module name
    {
        const size_t sep = path.find_last_of("/\\");
        std::string stem = (sep == std::string::npos) ? path : path.substr(sep + 1);
        const size_t dot = stem.find_last_of('.');
        if (dot != std::string::npos) stem = stem.substr(0, dot);
        const size_t n = stem.size() < sizeof(out.name) ? stem.size() : sizeof(out.name) - 1;
        memcpy(out.name, stem.c_str(), n);
        out.name[n] = '\0';
    }

    const uint64_t stack_size = 4 * 1024 * 1024;
    if (!out.stk.allocate(stack_size, below4))
        return fault_code(Fault::Allocation);

    // env/heap: GuestRegion members free themselves on any early return;
    // the stand-in registry is checked, so a full table fails closed
    const uint32_t envErr = buildFakeEnv(out);
    if (envErr != fault_code(Fault::None)) return envErr;
    registerApiStandins(out);
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
#ifdef _WIN64
    if (arch == 0) arch = 64; // default: this build's own architecture
#else
    if (arch == 0) arch = 32;
#endif

    stub::Loaded l{};
    uint32_t err = stub::loadShellcode(path, l, arch == 32);
    if (err != fault_code(Fault::None)) { printFault(err); return static_cast<int>(err); }

#ifndef _WIN64
    // 32-bit host build runs x86 shellcode only
    if (l.is64) { printFault(fault_code(Fault::Architecture)); return fault_code(Fault::Architecture); }
#endif

    stub::ExecAudit audit{}; // snapshot after load, guest pages are data only

    uint32_t result = fault_code(Fault::None);
    if (l.is64) result = stub::run64(l);
    else result = stub::run86(l);

    if (!audit.verify(l.img.base(), l.stk.base()))
        result = fault_code(Fault::Audit);
    if (result >= 0xE0000000u) { printFault(result); }
    return static_cast<int>(result);
}
