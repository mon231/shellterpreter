"""Prepend a layout-descriptor prologue to a peor-generated shellcode.

The interpreter never parses the shellcode it runs: it only emulates bytes
and reads the descriptor globals in the fake environment. This script is
test-pipeline infrastructure: it knows the peor blob embeds a PE image, and
bakes a tiny prologue that declares that layout (image base, .pdata, resource
directory) into the interpreter's known descriptor globals at run time.

Usage: python inject_desc.py <shellcode-file>
"""

import struct
import sys

# must match guest_environment.hpp
kDescRva = 0x1400
kDescMagic = 0x52445348  # 'RDSH'

kTebRva = 0x100  # TEB RVA inside the env region; TEB self-pointer lives there


def find_image(data):
    """Locate the embedded PE image the same way the old PeReader did:
    an MZ whose e_lfanew points at a real PE\\0\\0 inside the file."""
    for at in range(0, min(len(data), 0x10000) - 0x3F):
        if data[at:at + 2] != b"MZ":
            continue
        if at + 0x40 > len(data):
            continue
        lfanew = struct.unpack_from("<I", data, at + 0x3C)[0]
        if lfanew > 0x1000 or at + lfanew + 0x400 > len(data):
            continue
        if data[at + lfanew:at + lfanew + 4] != b"PE\x00\x00":
            continue
        return at, at + lfanew
    raise SystemExit("no embedded PE image found")


def main():
    path = sys.argv[1]
    data = open(path, "rb").read()
    img_off, hdr = find_image(data)
    machine = struct.unpack_from("<H", data, hdr + 4)[0]
    is64 = machine == 0x8664
    opt = hdr + 24
    magic = struct.unpack_from("<H", data, opt)[0]
    dd = opt + (0x70 if magic == 0x20B else 0x60)
    pdata_rva, pdata_size = struct.unpack_from("<II", data, dd + 3 * 8)
    res_rva = struct.unpack_from("<I", data, dd + 2 * 8)[0]
    entry_rva = struct.unpack_from("<I", data, opt + 16)[0]
    is_dll = struct.unpack_from("<H", data, hdr + 22)[0] & 0x2000 != 0

    d8 = kDescRva + 8 - kTebRva  # TEB self -> DESC+8 displacement

    if is64:
        stub = bytearray([
            0xE8, 0, 0, 0, 0,              # call L (pushes base+5)
            0x58,                          # L: pop rax        ; rax = base+5
        ])
        stub += bytes([0x48, 0x8D, 0x80]) + struct.pack("<i", 0)  # lea rax,[rax+d] patched below
        stub += bytes([
            0x65, 0x48, 0x8B, 0x0C, 0x25, 0x30, 0, 0, 0,  # mov rcx,gs:[30h] ; TEB self
            0x48, 0x8D, 0x89,                             # lea rcx,[rcx+d]  ; DESC+8
        ]) + struct.pack("<i", d8)
        stub += bytes([
            0x48, 0x89, 0x01,              # mov [rcx],rax     ; imageBase
            0x49, 0x89, 0xC3,              # mov r11,rax       ; keep imageBase
            0x48, 0x05,                    # add rax, imm32    ; + pdataRva
        ]) + struct.pack("<I", pdata_rva)
        stub += bytes([0x48, 0x89, 0x41, 0x08])                 # mov [rcx+8],rax  ; pdataVa
        stub += bytes([0xC7, 0x41, 0x10]) + struct.pack("<I", pdata_size)
        stub += bytes([0xC7, 0x41, 0xFC]) + struct.pack("<I", res_rva)  # DESC+4
        stub += bytes([0xC7, 0x41, 0xF8]) + struct.pack("<I", kDescMagic)  # commit
        if is_dll:
            stub += bytes([
                0x4C, 0x89, 0xD9,              # mov rcx,r11 ; hinst
                0xBA, 1, 0, 0, 0,              # mov edx,1   ; DLL_PROCESS_ATTACH
                0x45, 0x31, 0xC0,              # xor r8d,r8d ; reserved
            ])
    else:
        stub = bytearray([
            0xE8, 0, 0, 0, 0,              # call L
            0x58,                          # L: pop eax  ; eax = base+5
        ])
        stub += bytes([0x8D, 0x90]) + struct.pack("<i", 0)        # lea edx,[eax+d] patched below
        stub += bytes([
            0x64, 0xA1, 0x18, 0, 0, 0,     # mov eax,fs:[18h] ; TEB self
            0x05,                          # add eax, imm32   ; -> DESC+8
        ]) + struct.pack("<I", d8)
        stub += bytes([
            0x89, 0x10,                    # mov [eax],edx    ; imageBase (u32, high dword zero)
            0xC7, 0x40, 0xFC,              # mov dword [eax-4], resRva (DESC+4)
        ]) + struct.pack("<I", res_rva)
        stub += bytes([0xC7, 0x40, 0xF8]) + struct.pack("<I", kDescMagic)  # commit
        if is_dll:
            stub += bytes([
                0x89, 0xD1,                    # mov ecx,edx ; hinst
                0x8B, 0x14, 0x24,              # mov edx,[esp] ; the sentinel return address
                0x6A, 0x00,                    # push 0        ; reserved
                0x6A, 0x01,                    # push 1        ; DLL_PROCESS_ATTACH
                0x51,                          # push ecx      ; hinst
                0x52,                          # push edx      ; return address back on top
            ])

    s = len(stub)
    i2 = img_off + s  # the image shifts by the prologue length
    # patch the image-base lea displacement (rax/edx held base+5);
    # disp32 sits at offset 9 in x64 (after 48 8D 80) and 8 in x86 (after 8D 90)
    struct.pack_into("<i", stub, 9 if is64 else 8, i2 - 5)

    open(path, "wb").write(bytes(stub) + data)
    print(f"inject_desc: arch={'x64' if is64 else 'x86'} img={i2:#x} "
          f"pdata={pdata_rva:#x}+{pdata_size:#x} res={res_rva:#x} dll={is_dll} stub={s:#x}")


if __name__ == "__main__":
    main()
