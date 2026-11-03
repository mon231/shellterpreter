#include "pe_reader.hpp"
#include <cstring>

bool PeReader::scan(const std::vector<uint8_t>& bytes) {
    const uint8_t* data = bytes.data();
    const size_t length = bytes.size();
    for (size_t at = 0; at + 2 < length && at < 0x10000; ++at) {
        if (data[at] != 'M' || data[at + 1] != 'Z') continue;
        if (at + 0x40 > length) continue;
        const uint32_t header_offset = *reinterpret_cast<const uint32_t*>(&data[at + 0x3C]);
        // truncated or oversized header: the guest lied, keep scanning
        if (header_offset > 0x1000 || at + header_offset + 0x400 > length) continue;
        const uint8_t* header = &data[at + header_offset];
        if (!(header[0] == 'P' && header[1] == 'E' && header[2] == 0 && header[3] == 0)) continue;
        _machine = static_cast<uint16_t>(header[4] | (header[5] << 8));
        _has_image = true;
        _info.image_offset = at;
        const uint8_t* optional = header + 24;
        _info.entry_rva = *reinterpret_cast<const uint32_t*>(optional + 16);
        _info.is_dll = (*reinterpret_cast<const uint16_t*>(header + 22) & 0x2000) != 0;
        if (_machine == 0x8664) {
            _info.image_base = static_cast<uint32_t>(*reinterpret_cast<const uint64_t*>(optional + 24));
        } else {
            _info.image_base = *reinterpret_cast<const uint32_t*>(optional + 28);
        }
        _info.size_of_image = *reinterpret_cast<const uint32_t*>(optional + 56);
        return true;
    }
    return false;
}
