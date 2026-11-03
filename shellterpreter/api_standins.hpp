#pragma once
#include "vm.hpp"

namespace stub {

// Registers every compiled-in API stand-in in the guest's ApiTable.
// Checked: a full table fails the run closed instead of overflowing.
void registerApiStandins(Loaded& l);

} // namespace stub
