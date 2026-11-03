#pragma once
#include <cstdint>
#include <utility>
#include <vector>

namespace stub {

// Runtime self-audit contract (hard invariant 1): once the process has
// started, no page may ever change into or out of the executable set, and
// the guest's own pages must stay plain data. The snapshot is taken after
// loadShellcode; verify() is the single check main runs before exit.
class ExecAudit {
public:
    using ExecRange = std::pair<uint64_t, uint64_t>;

    // one sample of every committed executable region in the process
    ExecAudit();

    // false when an image/stack page became executable or W^X was broken,
    // or a new executable region appeared since construction
    bool verify(uint64_t imageAddr, uint64_t stackAddr) const;

private:
    std::vector<ExecRange> _ranges;
};

} // namespace stub
