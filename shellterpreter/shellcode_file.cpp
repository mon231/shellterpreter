#include "shellcode_file.hpp"
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

File::~File() {
    if (_handle) {
        CloseHandle(_handle);
        _handle = nullptr;
    }
}

bool File::open(const std::string& path) {
    _handle = CreateFileA(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                          OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    return _handle != INVALID_HANDLE_VALUE;
}

bool File::read(std::vector<uint8_t>& bytes) {
    LARGE_INTEGER size{};
    if (!GetFileSizeEx(_handle, &size) || size.QuadPart <= 0 ||
        size.QuadPart > 0x100000000ll) // one file, 4 GiB ceiling: the ReadFile
        return false;                 // byte count is a 32-bit DWORD below
    bytes.resize(static_cast<size_t>(size.QuadPart));
    DWORD loaded = 0;
    if (!ReadFile(_handle, bytes.data(), static_cast<DWORD>(bytes.size()), &loaded, nullptr) ||
        loaded != bytes.size())
        return false;
    return true;
}

bool ShellcodeFile::open(const std::string& path) {
    File file;
    if (!file.open(path) || !file.read(_bytes) || _bytes.empty())
        return false;
    return true;
}
