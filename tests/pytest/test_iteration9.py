import conftest
import pathlib
import struct

# Fail-closed and self-registration tests (iteration 9).
#
# The shellcode registers its own image layout with the interpreter by
# writing the descriptor globals in the emulated environment; the
# interpreter never parses the blob. These tests cover:
#   - a shellcode that never registers: image-relative services fail closed
#     (resources -> NULL, x64 table EH -> fault 0xE0000001; x86 chain-walk
#     EH needs no descriptor and still works)
#   - a shellcode that registers a wrong (skewed) image base: fail closed
#   - hand-crafted raw shellcodes (no PE bytes at all) that write the
#     descriptor themselves and read it back, proving the contract:
#     TEB self-pointer at gs:[30h]/fs:[18h] = env+0x100, descriptor at
#     env+0x1400, environment zero-initialized


def _run(exe_dir, name, extra=()):
    exe = exe_dir / "shellterpreter.exe"
    sc = exe_dir / f"{name}.shellcode"
    assert sc.exists(), f"{name}.shellcode was not built"
    return conftest.run([str(exe), str(sc), *extra])


def test_no_descriptor_resources_x64():
    r = _run(conftest.X64_DIR, "16_no_descriptor")
    assert r.returncode == 111, (conftest.win_code(r.returncode), r.stderr[-2000:])


def test_no_descriptor_resources_x86():
    r = _run(conftest.X86_DIR, "16_no_descriptor")
    assert r.returncode == 111, (conftest.win_code(r.returncode), r.stderr[-2000:])


def test_no_descriptor_eh_x64():
    # x64 table EH needs the .pdata pointer from the descriptor: fail closed
    r = _run(conftest.X64_DIR, "17_no_descriptor_eh")
    assert conftest.win_code(r.returncode) == 0xE0000001, (r.returncode, r.stderr[-2000:])


def test_no_descriptor_eh_x86():
    # x86 walks the FS:[0] chain of runtime VAs: no descriptor needed
    r = _run(conftest.X86_DIR, "17_no_descriptor_eh")
    assert r.returncode == 7, (conftest.win_code(r.returncode), r.stderr[-2000:])


def test_skew_descriptor_x64():
    r = _run(conftest.X64_DIR, "18_skew_descriptor")
    assert r.returncode == 111, (conftest.win_code(r.returncode), r.stderr[-2000:])


def test_skew_descriptor_x86():
    r = _run(conftest.X86_DIR, "18_skew_descriptor")
    assert r.returncode == 111, (conftest.win_code(r.returncode), r.stderr[-2000:])


# --- hand-crafted raw self-registration blobs -------------------------------

def build_raw(is64):
    """Blob: write a descriptor with self-computed values, read it back,
    return 0x2A if every field round-trips, 0x99 otherwise."""
    base = 5  # call $+5 pushes base+5; all image "addresses" are base-relative
    img = 0x1000
    pd = 0x2000
    res = 0x3000
    magic = 0x52445348
    code = bytearray()
    fixups = []  # (offset of rel32, target label)

    if is64:
        def lea_rax_r9(d):    return bytes([0x49, 0x8D, 0x85]) + struct.pack("<i", d)
        def lea_r10_r9(d):    return bytes([0x4D, 0x8D, 0x91]) + struct.pack("<i", d)
        code += bytes([0xE8, 0, 0, 0, 0])            # call L
        fixups.append((1, "L"))
        code += bytes([0x41, 0x58])                  # L: pop r9   (r9 = base+5)
        code += bytes([0x65, 0x48, 0x8B, 0x0C, 0x25, 0x30, 0, 0, 0])  # mov rcx,gs:[30h]
        code += bytes([0x48, 0x8D, 0x89]) + struct.pack("<i", 0x1308)  # lea rcx,[rcx+1308h] -> DESC+8
        code += lea_rax_r9(img - base)               # lea rax,[r9+img-base]
        code += bytes([0x48, 0x89, 0x01])            # mov [rcx],rax        ; imageBase
        code += lea_rax_r9(pd - base)
        code += bytes([0x48, 0x89, 0x41, 0x08])      # mov [rcx+8],rax      ; pdataVa
        code += bytes([0xC7, 0x41, 0x10]) + struct.pack("<I", 0x24)   # pdataSize
        code += bytes([0xC7, 0x41, 0xFC]) + struct.pack("<I", res)    # resRva
        code += bytes([0xC7, 0x41, 0xF8]) + struct.pack("<I", magic)  # commit
        # read back and verify
        code += bytes([0x8B, 0x41, 0xF8]) + bytes([0x3D]) + struct.pack("<I", magic)  # cmp [rcx-8],magic
        code += bytes([0x0F, 0x85, 0, 0, 0, 0]); fixups.append((len(code) - 4, "bad"))
        code += bytes([0x48, 0x8B, 0x01])            # mov rax,[rcx]
        code += lea_r10_r9(img - base)
        code += bytes([0x4C, 0x39, 0xD0])            # cmp rax,r10
        code += bytes([0x0F, 0x85, 0, 0, 0, 0]); fixups.append((len(code) - 4, "bad"))
        code += bytes([0x48, 0x8B, 0x41, 0x08])      # mov rax,[rcx+8]
        code += lea_r10_r9(pd - base)
        code += bytes([0x4C, 0x39, 0xD0])
        code += bytes([0x0F, 0x85, 0, 0, 0, 0]); fixups.append((len(code) - 4, "bad"))
        code += bytes([0x8B, 0x41, 0x10]) + bytes([0x3D]) + struct.pack("<I", 0x24)   # pdataSize
        code += bytes([0x0F, 0x85, 0, 0, 0, 0]); fixups.append((len(code) - 4, "bad"))
        code += bytes([0x8B, 0x41, 0xFC]) + bytes([0x3D]) + struct.pack("<I", res)    # resRva
        code += bytes([0x0F, 0x85, 0, 0, 0, 0]); fixups.append((len(code) - 4, "bad"))
        code += bytes([0xB8]) + struct.pack("<I", 0x2A)  # mov eax,0x2A
        code += bytes([0xC3])                        # ret
        code += bytes([0xB8]) + struct.pack("<I", 0x99)  # bad: mov eax,0x99
        code += bytes([0xC3])
    else:
        code += bytes([0xE8, 0, 0, 0, 0])            # call L
        fixups.append((1, "L"))
        code += bytes([0x5B])                        # L: pop ebx  (ebx = base+5)
        code += bytes([0x64, 0x8B, 0x15, 0x18, 0, 0, 0])  # mov edx,fs:[18h]
        code += bytes([0x81, 0xC2]) + struct.pack("<I", 0x1308)  # add edx,1308h -> DESC+8
        code += bytes([0x8D, 0x8B]) + struct.pack("<i", img - base)   # lea ecx,[ebx+img-base]
        code += bytes([0x89, 0x0A])                  # mov [edx],ecx        ; imageBase
        code += bytes([0x8D, 0x8B]) + struct.pack("<i", pd - base)
        code += bytes([0x89, 0x4A, 0x08])            # mov [edx+8],ecx      ; pdataVa
        code += bytes([0xC7, 0x42, 0x10]) + struct.pack("<I", 0x24)   # pdataSize
        code += bytes([0xC7, 0x42, 0xFC]) + struct.pack("<I", res)    # resRva
        code += bytes([0xC7, 0x42, 0xF8]) + struct.pack("<I", magic)  # commit
        code += bytes([0x8B, 0x4A, 0xF8]) + bytes([0x81, 0xF9]) + struct.pack("<I", magic)
        code += bytes([0x0F, 0x85, 0, 0, 0, 0]); fixups.append((len(code) - 4, "bad"))
        code += bytes([0x8B, 0x0A])                  # mov ecx,[edx]
        code += bytes([0x2B, 0xCB])                  # sub ecx,ebx
        code += bytes([0x81, 0xF9]) + struct.pack("<I", img - base)
        code += bytes([0x0F, 0x85, 0, 0, 0, 0]); fixups.append((len(code) - 4, "bad"))
        code += bytes([0x8B, 0x4A, 0x08])            # mov ecx,[edx+8]
        code += bytes([0x2B, 0xCB])
        code += bytes([0x81, 0xF9]) + struct.pack("<I", pd - base)
        code += bytes([0x0F, 0x85, 0, 0, 0, 0]); fixups.append((len(code) - 4, "bad"))
        code += bytes([0x8B, 0x4A, 0x10]) + bytes([0x81, 0xF9]) + struct.pack("<I", 0x24)
        code += bytes([0x0F, 0x85, 0, 0, 0, 0]); fixups.append((len(code) - 4, "bad"))
        code += bytes([0x8B, 0x4A, 0xFC]) + bytes([0x81, 0xF9]) + struct.pack("<I", res)
        code += bytes([0x0F, 0x85, 0, 0, 0, 0]); fixups.append((len(code) - 4, "bad"))
        code += bytes([0xB8]) + struct.pack("<I", 0x2A)
        code += bytes([0xC3])
        code += bytes([0xB8]) + struct.pack("<I", 0x99)  # bad:
        code += bytes([0xC3])

    labels = {}
    labels["L"] = 5   # the pop sits right after the 5-byte call
    labels["bad"] = len(code) - 5  # start of the final mov eax,0x99

    for off, target in fixups:
        if target == "L":
            rel = labels["L"] - (off + 4)
        else:
            rel = labels["bad"] - (off + 4)
        struct.pack_into("<i", code, off, rel)
    return bytes(code)


def test_raw_self_registration_x64(tmp_path):
    blob = tmp_path / "raw_selfreg_x64.shellcode"
    blob.write_bytes(build_raw(True))
    r = conftest.run([str(conftest.X64_DIR / "shellterpreter.exe"), str(blob)])
    assert conftest.win_code(r.returncode) == 0x2A, (conftest.win_code(r.returncode), r.stderr[-2000:])


def test_raw_self_registration_x86(tmp_path):
    blob = tmp_path / "raw_selfreg_x86.shellcode"
    blob.write_bytes(build_raw(False))
    r = conftest.run([str(conftest.X86_DIR / "shellterpreter.exe"), str(blob)])
    assert conftest.win_code(r.returncode) == 0x2A, (conftest.win_code(r.returncode), r.stderr[-2000:])


def test_raw_self_registration_x86_on_x64_interp(tmp_path):
    # arch comes from the flag only: the x64 interpreter runs the x86 blob
    blob = tmp_path / "raw_selfreg_x86.shellcode"
    blob.write_bytes(build_raw(False))
    r = conftest.run([str(conftest.X64_DIR / "shellterpreter.exe"), str(blob), "--x86"])
    assert conftest.win_code(r.returncode) == 0x2A, (conftest.win_code(r.returncode), r.stderr[-2000:])
