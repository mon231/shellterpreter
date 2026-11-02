#include "vm.hpp"

uint32_t stub::run86(Loaded&) {
    return FAULT_ARCH;
}
