import guestkit

# Iteration 14: batch D — whole-memory guest access, native bridge stubs for
# real kernel32/user32 functions, and the x64 syscall instruction. The guest
# discovers real export addresses through its own LoadLibraryA/GetProcAddress
# stand-ins (whitelisted modules now return their real bases); runs the real
# function through the bridge with the emulated register file.

# scratch inside env: 0x1200..0x13FF is free (kDescRva 0x1400, fake user32 0x1800)
SCR = 0x1200

# x64 prelude: rbx = TEB self (gs:[0x30] = env+0x100) - 0x100 = env base
PRE64 = guestkit.X64_PRE
# x86 prelude: ebx = fs:[0x18] self (env+0x100) - 0x100 = env base
PRE86 = guestkit.X86_PRE


def _load_gpa(module, func, off_mod, off_func):
    """LoadLibraryA(module) then GetProcAddress(hmod, func) via the stand-ins.

    The stand-ins live at envBase+0xA00 / +0xA10 (their addresses, not
    pointers), so the guest must compute the address in a register; x86
    stdcall calls push their args (kit's x86call keeps the order right).
    """
    x64 = (PRE64 + guestkit.puts("rbx", off_mod, module) + guestkit.puts("rbx", off_func, func)
           + f"lea rcx, [rbx+{off_mod:#x}]\n"
             "mov rax, rbx\nadd rax, 0xA00\ncall rax\n"       # LoadLibraryA
             "mov r14, rax\n"
             "mov rcx, r14\n"
           + f"lea rdx, [rbx+{off_func:#x}]\n"
             "mov rax, rbx\nadd rax, 0xA10\ncall rax\n")       # GetProcAddress
    x86 = (PRE86 + guestkit.puts("ebx", off_mod, module) + guestkit.puts("ebx", off_func, func)
           + f"lea ecx, [ebx+{off_mod:#x}]\n"
             "mov eax, ebx\nadd eax, 0xA00\n" + guestkit.x86call("eax", ["ecx"])
           + "mov edi, eax\n"
           + f"lea ecx, [ebx+{off_func:#x}]\n"
           + "mov eax, ebx\nadd eax, 0xA10\n"
           + guestkit.x86call("eax", ["edi", "ecx"])            # GetProcAddress
           )
    return x64, x86


_CASES = []


def case(name, asm64, asm86, expect):
    _CASES.append((name, asm64, asm86, expect))


# --- real kernel32 export through the bridge (stdlib lstrlenA) --------------
a64, a86 = _load_gpa("kernel32.dll", "lstrlenA", SCR, SCR + 0x20)
case("real_kernel32_lstrlen",
     a64 + guestkit.puts("rbx", SCR + 0x40, "hello")
       + f"lea rcx, [rbx+{SCR + 0x40:#x}]\ncall rax\n",
     a86 + guestkit.puts("ebx", SCR + 0x40, "hello")
       + f"lea ecx, [ebx+{SCR + 0x40:#x}]\n" + guestkit.x86call("eax", ["ecx"]),
     5)

# --- real user32 export through the bridge ----------------------------------
a64, a86 = _load_gpa("user32.dll", "IsWindowVisible", SCR, SCR + 0x20)
case("real_user32_iswindowvisible",
     a64 + "xor ecx, ecx\ncall rax\n",
     a86 + guestkit.x86call("eax", ["0"]),
     0)

# --- whole-memory access: real VirtualAlloc result is guest-usable ----------
a64, a86 = _load_gpa("kernel32.dll", "VirtualAlloc", SCR, SCR + 0x20)
case("wholememory_virtualalloc",
     a64 + ("xor ecx, ecx\nmov rdx, 0x1000\nmov r8d, 0x3000\nmov r9d, 4\ncall rax\n"
            "mov byte ptr [rax], 0x42\nmovzx eax, byte ptr [rax]\n"),
     a86 + (guestkit.x86call("eax", ["0", "0x1000", "0x3000", "4"])
            + "mov byte ptr [eax], 0x42\nmovzx eax, byte ptr [eax]\n"),
     0x42)

# --- guard page fails closed: guest read must fault, not crash the process ---
# PAGE_GUARD = 0x100 modifier; allocate RW | GUARD = 0x104. A bare 0x40 protect
# is PAGE_EXECUTE_READWRITE, so the guest would mint real RWX pages and the
# audit rejects that by design (0xE0000005) - wrong would-be test, see ledger
a64, a86 = _load_gpa("kernel32.dll", "VirtualAlloc", SCR, SCR + 0x20)
case("wholememory_guardpage_faults",
     a64 + ("xor ecx, ecx\nmov rdx, 0x1000\nmov r8d, 0x1000\nmov r9d, 0x104\ncall rax\n"
            "movzx eax, byte ptr [rax]\n"),
     a86 + (guestkit.x86call("eax", ["0", "0x1000", "0x1000", "0x104"])
            + "movzx eax, byte ptr [eax]\n"),
     0xE0000002)

# --- reserve-only region fails closed on read ---
case("wholememory_reserve_read_faults",
     a64 + ("xor ecx, ecx\nmov rdx, 0x1000\nmov r8d, 0x2000\nxor r9d, r9d\ncall rax\n"
            "movzx eax, byte ptr [rax]\n"),
     a86 + (guestkit.x86call("eax", ["0", "0x1000", "0x2000", "0"])
            + "movzx eax, byte ptr [eax]\n"),
     0xE0000002)

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
sysno_yield = guestkit.syscall_num("NtYieldExecution")
case("syscall_yield",
     f"mov eax, {sysno_yield:#x}\nsyscall\n",
     guestkit.X64_ONLY,
     0x40000024)  # real NtYieldExecution returns this warning-level status on
# this OS build; a fault or mismatched NTSTATUS would mean the dispatch
# never ran the real ntdll stub

sysno_qpc = guestkit.syscall_num("NtQueryPerformanceCounter")
case("syscall_marshal",
     f"mov qword ptr [rsp+0x30], 0\nlea rcx, [rsp+0x30]\nmov rdx, 0\n"
     f"mov eax, {sysno_qpc:#x}\nsyscall\n"
     "mov rax, [rsp+0x30]\ntest rax, rax\njnz ok\nmov eax, 0x2222\njmp done\n"
     "ok:\nmov eax, 0x11111111\ndone:\n",
     guestkit.X64_ONLY,
     0x11111111)

case("syscall_unknown_fails",
     "mov eax, 0x7777777\nsyscall\n",
     guestkit.X64_ONLY,
     0xE0000001)


def test_cases(tmp_path):
    for name, asm64, asm86, expect in _CASES:
        guestkit.run_case(name, asm64, asm86, expect, tmp_path)
