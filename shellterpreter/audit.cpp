#include "audit.hpp"
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

namespace {

std::vector<stub::ExecAudit::ExecRange> snapshot() {
    std::vector<stub::ExecAudit::ExecRange> out;
    SYSTEM_INFO system_info{};
    GetSystemInfo(&system_info);
    const uint8_t* addr = static_cast<const uint8_t*>(system_info.lpMinimumApplicationAddress);
    const uint8_t* max_addr = static_cast<const uint8_t*>(system_info.lpMaximumApplicationAddress);
    MEMORY_BASIC_INFORMATION mbi{};
    while (addr < max_addr) {
        if (VirtualQuery(addr, &mbi, sizeof(mbi)) == 0) break;
        const bool executable = (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ |
                                                PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
        if (mbi.State == MEM_COMMIT && executable && mbi.RegionSize > 0) {
            out.push_back({reinterpret_cast<uint64_t>(mbi.BaseAddress),
                           reinterpret_cast<uint64_t>(mbi.BaseAddress) + mbi.RegionSize});
        }
        addr = static_cast<const uint8_t*>(mbi.BaseAddress) + mbi.RegionSize;
    }
    return out;
}

bool pageHasExecute(uint64_t addr) {
    MEMORY_BASIC_INFORMATION mbi{};
    if (VirtualQuery(reinterpret_cast<void*>(addr), &mbi, sizeof(mbi)) == 0) return false;
    if (mbi.State != MEM_COMMIT) return false;
    return (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ |
                           PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
}

bool pageIsWriteAndExec(uint64_t addr) {
    MEMORY_BASIC_INFORMATION mbi{};
    if (VirtualQuery(reinterpret_cast<void*>(addr), &mbi, sizeof(mbi)) == 0) return false;
    if (mbi.State != MEM_COMMIT) return false;
    const bool writable = (mbi.Protect & (PAGE_READWRITE | PAGE_EXECUTE_READWRITE | PAGE_WRITECOPY)) != 0;
    const bool executable = (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ |
                                            PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
    return writable && executable;
}

bool noNewExec(const std::vector<stub::ExecAudit::ExecRange>& baseline) {
    std::vector<stub::ExecAudit::ExecRange> now = snapshot();
    if (now.size() != baseline.size()) return false;
    for (size_t i = 0; i < now.size(); ++i) {
        if (now[i].first != baseline[i].first) return false;
        if (now[i].second != baseline[i].second) return false;
    }
    return true;
}

} // namespace

namespace stub {

ExecAudit::ExecAudit() : _ranges(snapshot()) {}

bool ExecAudit::verify(uint64_t imageAddr, uint64_t stackAddr) const {
    if (pageHasExecute(imageAddr) || pageHasExecute(stackAddr))
        return false;
    if (pageIsWriteAndExec(imageAddr) || pageIsWriteAndExec(stackAddr))
        return false;
    return noNewExec(_ranges);
}

} // namespace stub

