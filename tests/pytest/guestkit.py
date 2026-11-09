"""Shared guest-test kit for the keystone blob suites (iteration11+).

One place for: keystone assembly (+ prologue/hlt tail), both-architecture
running, Win exit-code conversion, and the guest-side helpers that kept
drifting across per-file private copies.

Case semantics (run_case):
  asm86 explicit string  -> run x86 with it
  asm86 None             -> run x86 with the x64 asm after a plain 64->32
                            register rename (rIQ -> eIX); only safe for
                            asm that is genuinely portable
  asm86 X64_ONLY         -> skip x86 (never generate a fallback blob)

Gotcha that bit iteration14: x64-only asm (e.g. `syscall`) under the
None-fallback silently ran on x86 and read like a native-bridge fault.
Mark those cases X64_ONLY.
"""
import ctypes

import keystone as _ks
from keystone import Ks

import conftest

X64_ONLY = object()  # sentinel: this case has no x86 coverage

PRO64 = "sub rsp, 0x40\ncld\n"
PRO86 = "sub esp, 0x40\ncld\n"

_X86REG = {"rax": "eax", "rbx": "ebx", "rcx": "ecx", "rdx": "edx",
           "rsi": "esi", "rdi": "edi", "rbp": "ebp", "rsp": "esp"}

# TEB self-pointer preludes: gs:[0x30] (x64) / fs:[0x18] (x86) = env+0x100
X64_PRE = "mov rax, gs:[0x30]\nsub rax, 0x100\nmov rbx, rax\n"
X86_PRE = "mov eax, fs:[0x18]\nsub eax, 0x100\nmov ebx, eax\n"


def x86asm(asm):
    """Plain 64->32 register rename (rax->eax, ...). Nothing else."""
    return _rename(asm)


def _rename(asm):
    import re
    return re.sub(r"\b(rax|rbx|rcx|rdx|rsi|rdi|rbp|rsp)\b",
                  lambda m: _X86REG[m.group(0)], asm)


def blob(asm, is64):
    ks = Ks(_ks.KS_ARCH_X86, _ks.KS_MODE_64) if is64 else Ks(_ks.KS_ARCH_X86, _ks.KS_MODE_32)
    pro, _ = ks.asm(PRO64 if is64 else PRO86)
    body, _ = ks.asm(asm)
    tail, _ = ks.asm("hlt\n")
    return bytes(pro) + bytes(body) + bytes(tail)


def exit_code(codebytes, is64, tmp_path, tag):
    exe = conftest.X64_DIR if is64 else conftest.X86_DIR
    p = (tmp_path / tag).with_suffix(".shellcode")
    p.write_bytes(codebytes)
    r = conftest.run([str(exe / "shellterpreter.exe"), str(p)])
    rc = r.returncode
    code = conftest.win_code(rc) if rc < 0 else (rc & 0xFFFFFFFF)
    return code, r.stderr


def run_case(name, asm64, asm86, expect, tmp_path):
    """Run one case on x64, then x86 unless the case has no x86 version."""
    asm86_run = _rename(asm64) if (asm86 is None and asm64 is not None) else asm86
    for is64, asm, expect_ in (
        (True, asm64, expect[0] if isinstance(expect, tuple) else expect),
        (False, asm86_run, expect[1] if isinstance(expect, tuple) else expect),
    ):
        if asm is None or (is64 is False and asm is X64_ONLY):
            continue
        try:
            b = blob(asm, is64)
        except _ks.KsError as e:
            raise AssertionError(f"{name} [{'x64' if is64 else 'x86'}] failed to assemble: {e}")
        tag = name.replace("/", "_").replace(",", "_")
        code, err = exit_code(b, is64, tmp_path, tag)
        assert code == expect_, f"{name} [{'x64' if is64 else 'x86'}]: exit {code:#x} != {expect_:#x}\n{err[-800:]}"


def puts(base, off, value):
    """Dword stores writing value+NUL (zero-padded, one extra zero dword) at [base+off..]."""
    b = (value + "\0").encode()
    b += b"\x00" * ((-len(b)) % 4 + 4)
    out = []
    for i in range(0, len(b), 4):
        out.append(f"mov dword ptr [{base}+{off + i}], 0x{int.from_bytes(b[i:i + 4], 'little'):X}")
    return "\n".join(out) + "\n"


def x86call(fn_reg, args):
    """x86 stdcall call: push every arg (reverse) before `call <fn_reg>`.

    An x86 stand-in/bridge call must carry its args on the stack; a
    register-passed call reads garbage and guestStr fails -> returns 0.
    """
    return "".join(f"push {a}\n" for a in reversed(args)) + f"call {fn_reg}\n"


def syscall_num(func):
    """x64 runtime: parse ntdll's stub prologue (4C 8B D1 B8 imm32) -> syscall number."""
    nt = ctypes.WinDLL("ntdll.dll")
    addr = ctypes.cast(getattr(nt, func), ctypes.c_void_p).value
    buf = (ctypes.c_ubyte * 16)()
    ctypes.memmove(buf, addr, 16)
    b = bytes(buf)
    assert b[0:3] == b"\x4C\x8B\xD1" and b[3] == 0xB8, f"unexpected ntdll stub shape for {func}"
    return int.from_bytes(b[4:8], "little")
