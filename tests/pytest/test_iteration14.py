import conftest
import ctypes
import re

# Iteration 14: batch D — whole-memory guest access, native bridge stubs for
# real kernel32/user32 functions, and the x64 syscall instruction. The guest
# discovers real export addresses through its own LoadLibraryA/GetProcAddress
# stand-ins (whitelisted modules now return their real bases); runs the real
# function through the bridge with the emulated register file.

from keystone import Ks, KsError
import keystone as _ks

PRO64 = "sub rsp, 0x40\ncld\n"
PRO86 = "sub esp, 0x40\ncld\n"

_X86REG = {"rax": "eax", "rbx": "ebx", "rcx": "ecx", "rdx": "edx",
           "rsi": "esi", "rdi": "edi", "rbp": "ebp", "rsp": "esp"}


def _x86asm(asm):
    return re.sub(r"\b(rax|rbx|rcx|rdx|rsi|rdi|rbp|rsp)\b", lambda m: _X86REG[m.group(0)], asm)


def _blob(asm, is64):
    ks = Ks(_ks.KS_ARCH_X86, _ks.KS_MODE_64) if is64 else Ks(_ks.KS_ARCH_X86, _ks.KS_MODE_32)
    pro = ks.asm(PRO64 if is64 else PRO86)[0]
    body = ks.asm(asm)[0]
    tail = ks.asm("hlt\n")[0]
    return bytes(pro) + bytes(body) + bytes(tail)


def _exit_code(blobbytes, is64, tmp_path, tag):
    exe = conftest.X64_DIR if is64 else conftest.X86_DIR
    p = (tmp_path / tag).with_suffix(".shellcode")
    p.write_bytes(blobbytes)
    r = conftest.run([str(exe / "shellterpreter.exe"), str(p)])
    rc = r.returncode
    code = conftest.win_code(rc) if rc < 0 else (rc & 0xFFFFFFFF)
    return code, r.stderr


def _run_case(name, asm64, asm86, expect, tmp_path):
    for is64, asm in ((True, asm64), (False, asm86)):
        if asm is None:
            continue
        expect_ = (expect[0] if is64 else expect[1]) if isinstance(expect, tuple) else expect
        try:
            b = _blob(asm, is64)
        except KsError as e:
            raise AssertionError(f"{name} [{'x64' if is64 else 'x86'}] failed to assemble: {e}")
        code, err = _exit_code(b, is64, tmp_path, name)
        assert code == expect_, f"{name} [{'x64' if is64 else 'x86'}]: exit {code:#x} != {expect_:#x}\n{err[-800:]}"


def _puts(base, off, name):
    """Dword stores writing name+NUL (zero-padded, one extra zero dword) at [base+off..]."""
    b = (name + "\0").encode()
    b += b"\x00" * ((-len(b)) % 4 + 4)
    out = []
    for i in range(0, len(b), 4):
        out.append(f"mov dword ptr [{base}+{off + i}], 0x{int.from_bytes(b[i:i + 4], 'little'):X}")
    return "\n".join(out) + "\n"


# scratch inside env: 0x1200..0x13FF is free (kDescRva 0x1400, fake user32 0x1800)
SCR = 0x1200

_NONE = object()  # sentinel: no x86 asm (skip x86 instead of falling back)

# x64 prelude: rbx = TEB self (gs:[0x30] = env+0x100) - 0x100 = env base
PRE64 = "mov rax, gs:[0x30]\nsub rax, 0x100\nmov rbx, rax\n"
# x86 prelude: ebx = fs:[0x18] self (env+0x100) - 0x100 = env base
PRE86 = "mov eax, fs:[0x18]\nsub eax, 0x100\nmov ebx, eax\n"


def _load_gpa(module, func, off_mod, off_func):
    """LoadLibraryA(module) then GetProcAddress(hmod, func) via the stand-ins.

    The stand-ins live at envBase+0xA00 / +0xA10 (their addresses, not
    pointers), so the guest must compute the address in a register.
    """
    x64 = (PRE64 + _puts("rbx", off_mod, module) + _puts("rbx", off_func, func)
           + f"lea rcx, [rbx+{off_mod:#x}]\n"
             "mov rax, rbx\nadd rax, 0xA00\ncall rax\n"       # LoadLibraryA
             "mov r14, rax\n"
             "mov rcx, r14\n"
           + f"lea rdx, [rbx+{off_func:#x}]\n"
             "mov rax, rbx\nadd rax, 0xA10\ncall rax\n")       # GetProcAddress
    x86 = (PRE86 + _puts("ebx", off_mod, module) + _puts("ebx", off_func, func)
           + f"lea ecx, [ebx+{off_mod:#x}]\n"
             "mov eax, ebx\nadd eax, 0xA00\npush ecx\ncall eax\n"  # LoadLibraryA
             "mov edi, eax\n"
           + f"lea eax, [ebx+{off_func:#x}]\n"
             "push eax\npush edi\n"
             "mov eax, ebx\nadd eax, 0xA10\ncall eax\n")       # GetProcAddress
    return x64, x86


def _syscall_num(func):
    """x64 runtime: parse ntdll's stub prologue (4C 8B D1 B8 imm32) -> syscall number."""
    nt = ctypes.WinDLL("ntdll.dll")
    addr = ctypes.cast(getattr(nt, func), ctypes.c_void_p).value
    buf = (ctypes.c_ubyte * 16)()
    ctypes.memmove(buf, addr, 16)
    b = bytes(buf)
    assert b[0:3] == b"\x4C\x8B\xD1" and b[3] == 0xB8, f"unexpected ntdll stub shape for {func}"
    return int.from_bytes(b[4:8], "little")


_CASES = []


def case(name, asm64, asm86, expect):
    _CASES.append((name, asm64, asm86, expect))


# --- real kernel32 export through the bridge (stdlib lstrlenA) --------------
a64, a86 = _load_gpa("kernel32.dll", "lstrlenA", SCR, SCR + 0x20)
case("real_kernel32_lstrlen",
     a64 + _puts("rbx", SCR + 0x40, "hello")
       + f"lea rcx, [rbx+{SCR + 0x40:#x}]\ncall rax\n",
     a86 + _puts("ebx", SCR + 0x40, "hello")
       + f"lea ecx, [ebx+{SCR + 0x40:#x}]\npush ecx\ncall eax\n",
     5)

# --- real user32 export through the bridge ----------------------------------
a64, a86 = _load_gpa("user32.dll", "IsWindowVisible", SCR, SCR + 0x20)
case("real_user32_iswindowvisible",
     a64 + "xor ecx, ecx\ncall rax\n",
     a86 + "push 0\ncall eax\n",
     0)

# --- whole-memory access: real VirtualAlloc result is guest-usable ----------
a64, a86 = _load_gpa("kernel32.dll", "VirtualAlloc", SCR, SCR + 0x20)
case("wholememory_virtualalloc",
     a64 + ("xor ecx, ecx\nmov rdx, 0x1000\nmov r8d, 0x3000\nmov r9d, 4\ncall rax\n"
            "mov byte ptr [rax], 0x42\nmovzx eax, byte ptr [rax]\n"),
     a86 + ("push 4\npush 0x3000\npush 0x1000\npush 0\ncall eax\n"
            "mov byte ptr [eax], 0x42\nmovzx eax, byte ptr [eax]\n"),
     0x42)

# --- fail-closed names stay fail-closed -------------------------------------
a64, a86 = _load_gpa("kernel32.dll", "NopeNopeNope", SCR, SCR + 0x20)
case("gpa_failclosed",
     a64 + "or rax, rax\njnz bad\nmov eax, 0x11111111\njmp done\nbad:\nmov eax, 0x2222\ndone:\n",
     a86 + "or eax, eax\njnz bad\nmov eax, 0x11111111\njmp done\nbad:\nmov eax, 0x2222\ndone:\n",
     0x11111111)

# --- writes into real executable code pages fail closed ---------------------
a64, a86 = _load_gpa("kernel32.dll", "lstrlenA", SCR, SCR + 0x20)
case("wholememory_write_rx_faults",
     a64 + "mov byte ptr [rax], 0x42\n",
     a86 + "mov byte ptr [eax], 0x42\n",
     0xE0000002)

# --- x64-only: syscall dispatch through the bridge --------------------------
sysno_yield = _syscall_num("NtYieldExecution")
case("syscall_yield",
     f"mov eax, {sysno_yield:#x}\nsyscall\n",
     None,
     0x40000024)  # real NtYieldExecution returns this warning-level
# status on this OS build; any dispatch that completes without a fault
# proves the bridge ran the real ntdll stub

sysno_qpc = _syscall_num("NtQueryPerformanceCounter")
case("syscall_marshal",
     f"mov qword ptr [rsp+0x30], 0\nlea rcx, [rsp+0x30]\nmov rdx, 0\n"
     f"mov eax, {sysno_qpc:#x}\nsyscall\n"
     "mov rax, [rsp+0x30]\ntest rax, rax\njnz ok\nmov eax, 0x2222\njmp done\n"
     "ok:\nmov eax, 0x11111111\ndone:\n",
     None,
     0x11111111)

case("syscall_unknown_fails",
     "mov eax, 0x7777777\nsyscall\n",
     None,
     0xE0000001)


def test_cases(tmp_path):
    for name, asm64, asm86, expect in _CASES:
        _run_case(name, asm64, asm86, expect, tmp_path)
