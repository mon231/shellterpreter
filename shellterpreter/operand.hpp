#pragma once
#include <cstdint>
#include <variant>

namespace stub {

// One decoded operand: either a guest register slot or a resolved guest
// address. std::variant replaces the old Oprm struct where isReg decided
// which of the two fields meant anything; now each alternative carries only
// its own data.
struct OperandRegister { uint8_t index = 0; };
struct OperandMemory { uint64_t address = 0; };
using Operand = std::variant<OperandRegister, OperandMemory>;

} // namespace stub
