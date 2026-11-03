#pragma once
#include <cstdint>

// One RAII guest memory block: a single VirtualAlloc reservation that is
// always PAGE_READWRITE (hard invariant: guest pages are never executable).
// destructors release every allocation, so no early return can leak or
// half-free the loader's regions.
class GuestRegion {
public:
    GuestRegion() = default;
    GuestRegion(const GuestRegion&) = delete;
    GuestRegion& operator=(const GuestRegion&) = delete;
    GuestRegion(GuestRegion&& other) noexcept;
    GuestRegion& operator=(GuestRegion&& other) noexcept;
    ~GuestRegion();

    // below4: keep the block under 4 GiB even in the 64-bit build, because the
    // x86 core addresses everything through 32-bit registers and pointers.
    bool allocate(uint64_t size, bool below4);
    void release();

    uint8_t* data() const { return _data; }
    uint64_t base() const { return reinterpret_cast<uint64_t>(_data); }
    uint64_t size() const { return _size; }
    bool empty() const { return _data == nullptr; }

private:
    uint8_t* _data = nullptr;
    uint64_t _size = 0;
};
