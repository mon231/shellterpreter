"""Iteration 8: any shellcode, no PE-header reliance.

The interpreter must run arbitrary position-independent shellcode: no
embedded MZ/PE header is required, execution starts at offset 0, and the
architecture comes only from --x86/--x64 (default: the build's own arch).
An embedded header, even a fake one, must never override the caller.
"""

import conftest

# raw calc, identical bytes assemble for both archs (32-bit ops):
#   mov eax,0 ; mov ecx,10 ; L: add eax,ecx ; dec ecx ; jnz L ; ret
# returns 1+2+...+10 = 55
CALC = bytes([
    0xB8, 0x00, 0x00, 0x00, 0x00,   # mov eax,0
    0xB9, 0x0A, 0x00, 0x00, 0x00,   # mov ecx,10
    0x03, 0xC1,                     # add eax,ecx
    0xFF, 0xC9,                     # dec ecx
    0x75, 0xFA,                     # jnz L
    0xC3,                           # ret
])


def _run(exe_dir, sc, *flags):
    exe = exe_dir / "shellterpreter.exe"
    return conftest.run([str(exe), str(sc), *flags])


def test_raw_calc_x64_default(tmp_path):
    # no flag, no header: the 64-bit build defaults to its own arch
    sc = tmp_path / "calc64.bin"
    sc.write_bytes(CALC)
    r = _run(conftest.X64_DIR, sc)
    assert r.returncode == 55, (conftest.win_code(r.returncode), r.stderr[-2000:])


def test_raw_calc_x64_flag(tmp_path):
    sc = tmp_path / "calc64.bin"
    sc.write_bytes(CALC)
    r = _run(conftest.X64_DIR, sc, "--x64")
    assert r.returncode == 55, (conftest.win_code(r.returncode), r.stderr[-2000:])


def test_raw_calc_x86_default(tmp_path):
    # no flag, no header: the 32-bit build defaults to its own arch
    sc = tmp_path / "calc86.bin"
    sc.write_bytes(CALC)
    r = _run(conftest.X86_DIR, sc)
    assert r.returncode == 55, (conftest.win_code(r.returncode), r.stderr[-2000:])


def test_raw_calc_x86_flag(tmp_path):
    sc = tmp_path / "calc86.bin"
    sc.write_bytes(CALC)
    r = _run(conftest.X86_DIR, sc, "--x86")
    assert r.returncode == 55, (conftest.win_code(r.returncode), r.stderr[-2000:])


def test_raw_calc_cross_arch(tmp_path):
    # the dual-arch x64 interpreter runs raw x86 shellcode on request
    sc = tmp_path / "calc86.bin"
    sc.write_bytes(CALC)
    r = _run(conftest.X64_DIR, sc, "--x86")
    assert r.returncode == 55, (conftest.win_code(r.returncode), r.stderr[-2000:])


def _fake_pe_blob():
    """Calc code behind a fake embedded x64 PE header.

    Layout: jmp at 0 over everything, MZ at 5 with e_lfanew=0x40, PE\\0\\0 at
    0x45 claiming machine 0x8664, 0x400 bytes of padding (the scan's minimum
    image size), calc at 0x450. The header is well-formed enough for PeReader
    to find it -- and must still not decide anything.
    """
    b = bytearray(0x460)
    b[0:5] = b"\xE9\x4B\x04\x00\x00"          # jmp 0x450
    b[5:7] = b"MZ"
    b[0x41:0x45] = (0x40).to_bytes(4, "little")  # e_lfanew (at MZ+0x3C)
    b[0x45:0x49] = b"PE\x00\x00"
    b[0x49:0x4B] = (0x8664).to_bytes(2, "little")  # machine: x64
    b[0x450:0x450 + len(CALC)] = CALC
    return bytes(b)


def test_fake_embedded_x64_header_never_overrides_flag(tmp_path):
    sc = tmp_path / "fakepe.bin"
    sc.write_bytes(_fake_pe_blob())
    # --x86 must win: the blob runs on the x86 core and returns 55
    r = _run(conftest.X64_DIR, sc, "--x86")
    assert r.returncode == 55, (conftest.win_code(r.returncode), r.stderr[-2000:])
    # explicit --x64 also works (the code is arch-neutral here)
    r = _run(conftest.X64_DIR, sc, "--x64")
    assert r.returncode == 55, (conftest.win_code(r.returncode), r.stderr[-2000:])
