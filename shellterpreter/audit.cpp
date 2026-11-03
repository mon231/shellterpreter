#include "audit.hpp"
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

namespace stub {

std::vector<ExecRange> snapshotExecRanges() {
    std::vector<ExecRange> out;
    SYSTEM_INFO si{};
    GetSystemInfo(&si);
    const uint8_t* addr = static_cast<const uint8_t*>(si.lpMinimumApplicationAddress);
    const uint8_t* maxAddr = static_cast<const uint8_t*>(si.lpMaximumApplicationAddress);
    MEMORY_BASIC_INFORMATION mbi{};
    while (addr < maxAddr) {
        if (VirtualQuery(addr, &mbi, sizeof(mbi)) == 0) break;
        const bool ex = (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ |
                                        PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
        if (mbi.State == MEM_COMMIT && ex && mbi.RegionSize > 0) {
            out.push_back({reinterpret_cast<uint64_t>(mbi.BaseAddress),
                           reinterpret_cast<uint64_t>(mbi.BaseAddress) + mbi.RegionSize});
        }
        addr = static_cast<const uint8_t*>(mbi.BaseAddress) + mbi.RegionSize;
    }
    return out;
}

bool verifyNoNewExec(const std::vector<ExecRange>& baseline) {
    std::vector<ExecRange> now = snapshotExecRanges();
    if (now.size() != baseline.size()) return false;
    for (size_t i = 0; i < now.size(); ++i) {
        if (now[i].first != baseline[i].first) return false;
        if (now[i].second != baseline[i].second) return false;
    }
    return true;
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
    const bool wr = (mbi.Protect & (PAGE_READWRITE | PAGE_EXECUTE_READWRITE | PAGE_WRITECOPY)) != 0;
    const bool ex = (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ |
                                    PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
    return wr && ex;
}

}
