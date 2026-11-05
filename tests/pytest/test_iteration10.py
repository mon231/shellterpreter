import conftest
import struct

# Malformed-descriptor fail-closed tests (iteration 10).
#
# The descriptor contract says: a blob that registers nothing, or registers
# garbage, must fail closed - never crash the interpreter, never fake a pass.
# These tests use raw hand-crafted shellcodes (no PE bytes) that write a
# descriptor variant and then call the RaiseException stand-in directly
# (env.base()+0x1E28, env base derived from the TEB self-pointer), forcing
# the interpreter's EH dispatch to consume whatever was registered.

MAGIC = 0x52445348
ST_RAISE = 0x1E28


def _exit(r):
    return conftest.win_code(r.returncode)


# --- x64 blobs ---------------------------------------------------------------

def _x64_desc_blob(magic, fields):
    """fields = (img_lo, img_hi, pd_lo, pd_hi, size) dword stores, or None."""
    c = bytearray()
    c += bytes([0xE8, 0, 0, 0, 0])                                  # call L
    c += bytes([0x41, 0x58])                                        # L: pop r9
    c += bytes([0x65, 0x48, 0x8B, 0x0C, 0x25, 0x30, 0, 0, 0])       # mov rcx,gs:[30h]
    c += bytes([0x48, 0x81, 0xE9]) + struct.pack("<I", 0x100)       # sub rcx,100h -> env base
    c += bytes([0x4C, 0x8B, 0xD1])                                  # mov r10,rcx
    c += bytes([0x48, 0x8D, 0x89]) + struct.pack("<I", 0x1408)      # lea rcx,[rcx+1408h] -> DESC+8
    if magic is not None:
        c += bytes([0xC7, 0x41, 0xF8]) + struct.pack("<I", magic)   # mov dword [rcx-8],magic
    if fields is not None:
        for off, val in zip((0, 4, 8, 0xC, 0x10), fields):
            c += bytes([0xC7, 0x41, off]) + struct.pack("<I", val)
    c += bytes([0xB9]) + struct.pack("<I", 1)                       # mov ecx,1 (code)
    c += bytes([0x31, 0xD2])                                        # xor edx,edx
    c += bytes([0x45, 0x31, 0xC0])                                  # xor r8d,r8d
    c += bytes([0x45, 0x31, 0xC9])                                  # xor r9d,r9d
    c += bytes([0x49, 0x8D, 0x82]) + struct.pack("<I", ST_RAISE)    # lea rax,[r10+ST_RAISE]
    c += bytes([0xFF, 0xD0])                                        # call rax
    c += bytes([0xB8]) + struct.pack("<I", 0x99)                    # reached only if raise returns
    c += bytes([0xC3])
    return bytes(c)


# --- x86 blobs ---------------------------------------------------------------

def _x86_desc_blob(magic, fields):
    c = bytearray()
    c += bytes([0xE8, 0, 0, 0, 0])                                  # call L
    c += bytes([0x5B])                                              # L: pop ebx
    c += bytes([0x64, 0x8B, 0x15, 0x18, 0, 0, 0])                   # mov edx,fs:[18h]
    c += bytes([0x81, 0xEA]) + struct.pack("<I", 0x100)             # sub edx,100h -> env base
    c += bytes([0x89, 0xD6])                                        # mov esi,edx
    c += bytes([0x81, 0xC2]) + struct.pack("<I", 0x1408)            # add edx,1408h -> DESC+8
    if magic is not None:
        c += bytes([0xC7, 0x42, 0xF8]) + struct.pack("<I", magic)   # mov dword [edx-8],magic
    if fields is not None:
        for off, val in zip((0, 4, 8, 0xC, 0x10), fields):
            if off == 0:
                c += bytes([0xC7, 0x02]) + struct.pack("<I", val)   # mov dword [edx],val
            else:
                c += bytes([0xC7, 0x42, off]) + struct.pack("<I", val)
    c += bytes([0x6A, 0x00]) * 3                                    # push 0 (args/nargs/flags)
    c += bytes([0x6A, 0x01])                                        # push 1 (code)
    c += bytes([0x89, 0xF0])                                        # mov eax,esi
    c += bytes([0x05]) + struct.pack("<I", ST_RAISE)                # add eax,ST_RAISE
    c += bytes([0xFF, 0xD0])                                        # call eax
    c += bytes([0xB8]) + struct.pack("<I", 0x99)                    # reached only if raise returns
    c += bytes([0xC2, 0x10, 0x00])                                  # ret 10h (stdcall cleanup)
    return bytes(c)


GARBAGE = (0xAAAAAAAA, 0xAAAAAAAA, 0xBBBBBBBB, 0xBBBBBBBB, 0xCCCCCCCC)
PLAUSIBLE = (0x00010000, 0, 0x00018000, 0, 0x18)  # in-range-looking but empty .pdata


def test_raw_raise_no_handler_x86(tmp_path):
    # x86 EH walks the FS:[0] chain and needs no descriptor; a raw blob with
    # no registered handler must fail closed, not crash.
    blob = tmp_path / "x86_no_handler.shellcode"
    blob.write_bytes(_x86_desc_blob(None, None))
    r = conftest.run([str(conftest.X86_DIR / "shellterpreter.exe"), str(blob)])
    assert _exit(r) == 0xE0000001, (_exit(r), r.stderr[-2000:])


def test_raw_desc_zero_fields_raise_x64(tmp_path):
    # magic committed but every field zero: no image base -> fail closed
    blob = tmp_path / "x64_desc_zero.shellcode"
    blob.write_bytes(_x64_desc_blob(MAGIC, None))
    r = conftest.run([str(conftest.X64_DIR / "shellterpreter.exe"), str(blob)])
    assert _exit(r) == 0xE0000001, (_exit(r), r.stderr[-2000:])


def test_raw_desc_garbage_raise_x64(tmp_path):
    # magic committed, absurd field values: must be rejected without
    # dereferencing anything
    blob = tmp_path / "x64_desc_garbage.shellcode"
    blob.write_bytes(_x64_desc_blob(MAGIC, GARBAGE))
    r = conftest.run([str(conftest.X64_DIR / "shellterpreter.exe"), str(blob)])
    assert _exit(r) == 0xE0000001, (_exit(r), r.stderr[-2000:])


def test_raw_desc_plausible_empty_raise_x64(tmp_path):
    # magic committed, in-range-looking .pdata pointer that scans as zeros:
    # no function match -> fail closed
    blob = tmp_path / "x64_desc_plausible.shellcode"
    blob.write_bytes(_x64_desc_blob(MAGIC, PLAUSIBLE))
    r = conftest.run([str(conftest.X64_DIR / "shellterpreter.exe"), str(blob)])
    assert _exit(r) == 0xE0000001, (_exit(r), r.stderr[-2000:])


def test_raw_desc_garbage_raise_x86(tmp_path):
    # x86 ignores the descriptor entirely; the no-handler rule still holds
    blob = tmp_path / "x86_desc_garbage.shellcode"
    blob.write_bytes(_x86_desc_blob(MAGIC, GARBAGE))
    r = conftest.run([str(conftest.X86_DIR / "shellterpreter.exe"), str(blob)])
    assert _exit(r) == 0xE0000001, (_exit(r), r.stderr[-2000:])


# --- positive path: a raw blob with no PE bytes handles its own raise -------

ST_CSH = 0x1DD0  # __C_specific_handler stand-in, env-relative (guest_environment.hpp)


def build_raw_seh_x64():
    """Blob: register an honest descriptor whose .pdata/unwind info/scope
    table are hand-built data inside the blob, then RaiseException(1). The
    scope filter accepts code 1, the handler resumes with eax=0x2A which
    becomes the exit code. Proves the descriptor contract is complete: the
    interpreter walks EH metadata it never parsed, declared purely by the
    guest."""
    code = bytearray()
    fixups = []  # (byte offset of rel32, key)

    # top-level: register descriptor, call stub, ret (exit code = eax)
    code += bytes([0xE8, 0, 0, 0, 0]); fixups.append((len(code) - 4, "L1"))
    code += bytes([0x41, 0x59])                                        # L1: pop r9 (base+5)
    code += bytes([0x4D, 0x8B, 0xD1])                                  # mov r10,r9
    code += bytes([0x65, 0x48, 0x8B, 0x0C, 0x25, 0x30, 0, 0, 0])       # mov rcx,gs:[30h]
    code += bytes([0x48, 0x81, 0xE9]) + struct.pack("<I", 0x100)       # sub rcx,100h -> env base
    code += bytes([0x48, 0x8D, 0x89]) + struct.pack("<I", 0x1408)      # lea rcx,[rcx+1408h] -> DESC+8
    code += bytes([0x49, 0x8D, 0x41, 0xFB])                            # lea rax,[r9-5] -> base
    code += bytes([0x48, 0x89, 0x01])                                  # mov [rcx],rax      ; imageBase
    code += bytes([0x49, 0x8D, 0x81]); fixups.append((len(code), "pdata"))
    code += b"\0\0\0\0"                                                # lea rax,[r9+P-5]
    code += bytes([0x48, 0x89, 0x41, 0x08])                            # mov [rcx+8],rax    ; pdataVa
    code += bytes([0xC7, 0x41, 0x10]) + struct.pack("<I", 12)          # pdataSize = 12
    code += bytes([0xC7, 0x41, 0xFC]) + struct.pack("<I", 0)           # resRva = 0
    code += bytes([0xC7, 0x41, 0xF8]) + struct.pack("<I", MAGIC)       # commit magic
    code += bytes([0xE8, 0, 0, 0, 0]); fixups.append((len(code) - 4, "stub"))
    code += bytes([0xC3])                                              # ret (never reached normally)
    stub_off = len(code)

    # stub: write the personality slot (needs the runtime env base), raise
    code += bytes([0x65, 0x48, 0x8B, 0x0C, 0x25, 0x30, 0, 0, 0])       # mov rcx,gs:[30h]
    code += bytes([0x48, 0x81, 0xE9]) + struct.pack("<I", 0x100)       # sub rcx,100h
    code += bytes([0x48, 0x8D, 0x89]) + struct.pack("<I", ST_CSH)      # lea rcx,[rcx+ST_CSH]
    code += bytes([0x49, 0x8D, 0x82]); fixups.append((len(code), "slot"))
    code += b"\0\0\0\0"                                                # lea rax,[r10+SLOT]
    code += bytes([0x48, 0x89, 0x08])                                  # mov [rax],rcx      ; slotVal
    code += bytes([0xB9]) + struct.pack("<I", 1)                       # mov ecx,1 (code)
    code += bytes([0x31, 0xD2])                                        # xor edx,edx
    code += bytes([0x45, 0x31, 0xC0])                                  # xor r8d,r8d
    code += bytes([0x45, 0x31, 0xC9])                                  # xor r9d,r9d
    code += bytes([0x48, 0x8B, 0x00])                                  # mov rax,[rax]      ; slotVal
    code += bytes([0x48, 0x05]) + struct.pack("<I", ST_RAISE - ST_CSH) # add rax,raise-csh
    code += bytes([0xFF, 0xD0])                                        # call rax (RaiseException)
    code += bytes([0xC3])                                              # ret

    # data section
    H = len(code)
    code += bytes([0xFF, 0x25]); fixups.append((len(code), "thunk"))
    code += b"\0\0\0\0"                                                # FF 25 <SLOT-(H+6)>
    SLOT = len(code)
    code += b"\0" * 8                                                  # slot qword, written at runtime
    FILTER = len(code)
    code += bytes([0x8B, 0x01])                                        # mov eax,[rcx]   -> EXCEPTION_RECORD
    code += bytes([0x8B, 0x00])                                        # mov eax,[rax]   -> code
    code += bytes([0x3D]) + struct.pack("<I", 1)                       # cmp eax,1
    code += bytes([0x75, 0x06])                                        # jne bad
    code += bytes([0xB8]) + struct.pack("<I", 1)                       # mov eax,EXECUTE_HANDLER
    code += bytes([0xC3])                                              # ret
    code += bytes([0x31, 0xC0])                                        # bad: xor eax,eax (CONTINUE_SEARCH)
    code += bytes([0xC3])                                              # ret
    HANDLER = len(code)
    code += bytes([0xB8]) + struct.pack("<I", 0x2A)                    # mov eax,0x2A
    code += bytes([0xC3])                                              # ret
    U = len(code)
    code += bytes([0x19, 0, 0, 0])                                     # ver=1, flags=EHANDLER|UHANDLER, cnt=0
    code += struct.pack("<I", H)                                       # handler thunk RVA
    code += struct.pack("<I", 1)                                       # scope-table count (= dRva slot)
    code += struct.pack("<IIII", 0, 0x1000, FILTER, HANDLER)           # sb, se, filter, handler
    P = len(code)
    code += struct.pack("<III", 0, 0x1000, U)                          # RUNTIME_FUNCTION: begin, end, unwind

    labels = {"stub": stub_off, "pdata": P, "slot": SLOT, "thunk": SLOT - (H + 6)}
    for off, key in fixups:
        if key == "L1":
            struct.pack_into("<i", code, off, 5 - (off + 4))          # pop sits at offset 5
        elif key == "stub":
            struct.pack_into("<i", code, off, labels["stub"] - (off + 4))
        elif key in ("pdata", "slot"):
            # r10/r9 hold base+5: effective = reg + disp = base+target
            struct.pack_into("<i", code, off, labels[key] - 5)
        else:  # thunk: FF 25 rel32 from rip = H+6
            struct.pack_into("<i", code, off, labels["thunk"])
    return bytes(code)


def test_raw_seh_handled_x64(tmp_path):
    blob = tmp_path / "raw_seh_x64.shellcode"
    blob.write_bytes(build_raw_seh_x64())
    r = conftest.run([str(conftest.X64_DIR / "shellterpreter.exe"), str(blob)])
    assert _exit(r) == 0x2A, (_exit(r), r.stderr[-2000:])

