#include "instruction_decoder.hpp"

namespace stub {

namespace {
// operand sizes 1,2,4,8 are the legal widths masks/ bit counts; slot 0 and
// the non-power-of-two indexes only exist to keep the next power of two
constexpr uint64_t kWmask[9] = { 0, 0xFF, 0xFFFF, 0, 0xFFFFFFFFull, 0, 0, 0, ~0ull };
constexpr unsigned kWbits[9] = { 0, 8, 16, 0, 32, 0, 0, 0, 64 };
} // anonymous namespace

uint64_t maskSz(int size) { return kWmask[size]; }
unsigned bitsSz(int size) { return kWbits[size]; }

uint64_t sext(int from, uint64_t value) {
    switch (from) {
    case 1: return static_cast<uint64_t>(static_cast<int64_t>(static_cast<int8_t>(value & 0xFF)));
    case 2: return static_cast<uint64_t>(static_cast<int64_t>(static_cast<int16_t>(value & 0xFFFF)));
    case 4: return static_cast<uint64_t>(static_cast<int64_t>(static_cast<int32_t>(value & 0xFFFFFFFFull)));
    default: return value;
    }
}

unsigned popcnt8(uint8_t value) {
    unsigned n = 0;
    while (value) { n += value & 1; value >>= 1; }
    return n;
}

} // namespace stub
