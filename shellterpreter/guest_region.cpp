#include "guest_region.hpp"
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

GuestRegion::GuestRegion(GuestRegion&& other) noexcept
    : _data(other._data), _size(other._size) {
    other._data = nullptr;
    other._size = 0;
}

GuestRegion& GuestRegion::operator=(GuestRegion&& other) noexcept {
    if (this != &other) {
        release();
        _data = other._data;
        _size = other._size;
        other._data = nullptr;
        other._size = 0;
    }
    return *this;
}

GuestRegion::~GuestRegion() {
    release();
}

void GuestRegion::release() {
    if (_data) {
        VirtualFree(_data, 0, MEM_RELEASE);
        _data = nullptr;
    }
    _size = 0;
}

bool GuestRegion::allocate(uint64_t size, bool below4) {
    release();
    if (below4) {
        // reservation addresses climb 64 KiB at a time until one sticks
        for (uintptr_t at = 0x10000; at < 0x80000000ull; at += 0x10000) {
            _data = static_cast<uint8_t*>(VirtualAlloc(
                reinterpret_cast<void*>(at), size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
            if (_data) {
                _size = size;
                return true;
            }
        }
    }
    _data = static_cast<uint8_t*>(
        VirtualAlloc(nullptr, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    if (_data) _size = size;
    return _data != nullptr;
}
