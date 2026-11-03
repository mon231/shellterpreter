#pragma once
#include <cstdint>
#include <utility>
#include <vector>

namespace stub {

using ExecRange = std::pair<uint64_t, uint64_t>;

std::vector<ExecRange> snapshotExecRanges();
bool verifyNoNewExec(const std::vector<ExecRange>& baseline);
bool pageHasExecute(uint64_t addr);
bool pageIsWriteAndExec(uint64_t addr);

}
