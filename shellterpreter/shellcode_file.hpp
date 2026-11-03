#pragma once
#include <cstdint>
#include <string>
#include <vector>

// RAII file access for the loader: open/ReadFile/CloseHandle behind the
// destructor, so no early return in the caller can leak the handle.
class File {
public:
    File() = default;
    File(const File&) = delete;
    File& operator=(const File&) = delete;
    ~File();

    bool open(const std::string& path);
    bool read(std::vector<uint8_t>& bytes);

private:
    void* _handle = nullptr;
};

// The guest program to emulate: its bytes once, read for good.
class ShellcodeFile {
public:
    bool open(const std::string& path);
    const std::vector<uint8_t>& bytes() const { return _bytes; }

private:
    std::vector<uint8_t> _bytes;
};
