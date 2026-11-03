#include "fault.hpp"

uint32_t fault_code(Fault value) {
    return static_cast<uint32_t>(value);
}

std::string fault_message(uint32_t fault) {
    switch (static_cast<Fault>(fault)) {
    case Fault::None:
        return "success";
    case Fault::UnsupportedInstruction:
        return "unimplemented opcode";
    case Fault::OutsideMemory:
        return "access outside emulated memory";
    case Fault::BadFile:
        return "bad shellcode file";
    case Fault::Allocation:
        return "memory allocation failed";
    case Fault::Audit:
        return "runtime self-audit violation";
    case Fault::Halt:
        return "hlt executed";
    case Fault::Architecture:
        return "architecture mismatch or core not built";
    case Fault::Argument:
        return "bad command line";
    case Fault::Budget:
        return "instruction budget exhausted";
    default:
        return "unknown state";
    }
}
