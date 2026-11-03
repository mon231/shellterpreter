#include "api_table.hpp"

namespace stub {

bool ApiTable::add(const ApiEntry& entry) {
    if (_count >= max_entries) return false;
    _entries[_count++] = entry;
    return true;
}

const ApiEntry* ApiTable::find(uint64_t addr) const {
    for (uint32_t i = 0; i < _count; ++i)
        if (_entries[i].addr == addr) return &_entries[i];
    return nullptr;
}

} // namespace stub
