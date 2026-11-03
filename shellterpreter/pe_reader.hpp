#pragma once
#include <cstdint>
#include <vector>

// What the embedded PK header tells us about the guest. `image_offset` is the
// file position of the MZ; the interpreter maps the whole blob (including the
// peor stubs that live before it) at one base, so addresses like
// image_offset + entry_rva resolve there.
struct PeInfo {
    uint64_t image_offset = 0;
    uint32_t entry_rva = 0;
    uint32_t image_base = 0;
    uint32_t size_of_image = 0;
    bool is_dll = false; // IMAGE_FILE_DLL: entry runs as DllMain
};

// Scans a shellcode blob for the real MZ/PE header. peor elements carry decoy
// MZ strings (short e_lfanew plausible), so the scan accepts only headers
// where the e_lfanew points at a real PE\0\0 signature inside the file.
// No header: no image, the caller picks the architecture explicitly.
class PeReader {
public:
    bool scan(const std::vector<uint8_t>& bytes);

    const PeInfo& info() const { return _info; }
    uint16_t machine() const { return _machine; }
    bool has_image() const { return _has_image; }

private:
    PeInfo _info;
    uint16_t _machine = 0;
    bool _has_image = false;
};
