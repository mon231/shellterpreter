#pragma once
#include <cstdint>
#include <string>

// The interpreter's failure contract: every early exit states itself as one
// of these codes; the process exit code carries the numeric value.
enum class Fault : uint32_t {
    None = 0x00000000u,
    UnsupportedInstruction = 0xE0000001u,
    OutsideMemory = 0xE0000002u,
    BadFile = 0xE0000003u,
    Allocation = 0xE0000004u,
    Audit = 0xE0000005u,
    Halt = 0xE0000006u,
    Architecture = 0xE0000007u,
    Argument = 0xE0000008u,
    Budget = 0xE0000009u,
};

uint32_t fault_code(Fault value);
std::string fault_message(uint32_t fault);
