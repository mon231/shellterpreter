import conftest
import struct

# Iteration 11: integer-opcode coverage (batch A of "all user-mode opcodes").
#
# Raw keystone-assembled blobs: body runs on the interpreter, writes its
# result into EAX, and terminates with hlt (exit code = EAX). Expected
# values are real-x86 semantics; several expected CRC values are computed
# here with the same Castagnoli algorithm the hardware uses.

from keystone import Ks, KsError
import keystone as _ks

PRO64 = "sub rsp, 0x40\ncld\n"
PRO86 = "sub esp, 0x40\ncld\n"


_CRC32B64 = "mov rbx, 0x31\nxor eax, eax\ncrc32 eax, bl"
_CRC32B86 = "mov ebx, 0x31\nxor eax, eax\ncrc32 eax, bl"
_CRC32Q = "mov rbx, 0x1122334455667788\nmov rax, 0\ncrc32 rax, rbx"


def _crc32c_intel(init32, data):
    crc = ~init32 & 0xFFFFFFFF
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ (0x82F63B78 if crc & 1 else 0)
    return ~crc & 0xFFFFFFFF


CRC32B_EXPECT = _crc32c_intel(0, struct.pack("<B", 0x31))
CRC32Q_EXPECT = _crc32c_intel(0, struct.pack("<Q", 0x1122334455667788))


KS64 = Ks(Ks.KS_ARCH_X86, Ks.KS_MODE_64) if hasattr(Ks, "KS_ARCH_X86") else None


def _blob(asm, is64):
    ks = Ks(_ks.KS_ARCH_X86, _ks.KS_MODE_64) if is64 else Ks(_ks.KS_ARCH_X86, _ks.KS_MODE_32)
    pro, _ = ks.asm(PRO64 if is64 else PRO86)
    body, _ = ks.asm(asm)
    tail, _ = ks.asm("hlt\n")
    return bytes(pro) + bytes(body) + bytes(tail)


def _exit_code(blobbytes, is64, tmp_path):
    exe = conftest.X64_DIR if is64 else conftest.X86_DIR
    p = (tmp_path / ("probe64" if is64 else "probe86")).with_suffix(".shellcode")
    p.write_bytes(blobbytes)
    r = conftest.run([str(exe / "shellterpreter.exe"), str(p)])
    rc = r.returncode
    code = conftest.win_code(rc) if rc < 0 else (rc & 0xFFFFFFFF)
    return code, r.stderr


def _run_case(name, asm64, asm86, expect, tmp_path):
    # asm86 None = same asm on both; asm86 "" = x64-only
    for is64, asm in ((True, asm64), (False, asm86 if (asm86 is not None and asm86 != "") else (None if asm86 == "" else asm64))):
        if asm is None:
            continue
        try:
            b = _blob(asm, is64)
        except KsError as e:
            raise AssertionError(f"{name} [{'x64' if is64 else 'x86'}] failed to assemble: {e}")
        code, err = _exit_code(b, is64, tmp_path)
        assert code == expect, f"{name} [{'x64' if is64 else 'x86'}]: exit {code:#x} != {expect:#x}\n{err[-800:]}"


# (name, x64 asm, x86 asm-or-None (=x64), expected exit)
CASES = [
    # mul / imul family
    ("mul64high", "mov rax, 0x8000000000000000\nmov rbx, 2\nmul rbx\nmov eax, edx",
                  "mov eax, 0x80000000\nmov ebx, 2\nmul ebx\nmov eax, edx", 1),
    ("mul64low", "mov rax, 0x80000001\nmov rbx, 2\nmul rbx",
                 "mov eax, 0x80000001\nmov ebx, 2\nmul ebx", 2),
    ("mul8", "mov al, 0x10\nmov bl, 3\nmul bl\nmovzx eax, ax", None, 0x30),
    ("imul64imm", "mov rax, 3\nimul rax, rax, 7", "mov eax, 3\nimul eax, eax, 7", 21),
    ("imul64mem", "mov rax, 4\nmov qword ptr [rsp], rax\nimul rdi, qword ptr [rsp], 3\nmov eax, edi",
                  "mov eax, 4\nmov dword ptr [esp], eax\nimul ebx, dword ptr [esp], 3\nmov eax, ebx", 12),
    ("imulAF", "mov rax, 5\nmov rbx, 4\nimul rax, rbx", "mov eax, 5\nmov ebx, 4\nimul eax, ebx", 20),
    # rotates (cf shown in the high byte of the exit)
    ("rolres", "mov eax, 0x80000001\nrol eax, 1", None, 0x00000003),
    ("rolcf", "mov eax, 0x80000001\nrol eax, 1\nsetc al\nmovzx eax, al", None, 1),
    ("rorres", "mov eax, 3\nror eax, 1", None, 0x80000001),
    ("rorcf", "mov eax, 3\nror eax, 1\nsetc al\nmovzx eax, al", None, 1),
    ("rclbc", "clc\nmov eax, 0x80000001\nrcl eax, 1\nsetc cl\nmovzx ecx, cl\nshl ecx, 8\nor eax, ecx", None, 0x102),
    ("rcrbc", "stc\nmov eax, 1\nrcr eax, 1\nsetc cl\nmovzx ecx, cl\nshl ecx, 8\nor eax, ecx", None, 0x80000100),
    # shld/shrd
    ("shldimm", "mov eax, 0x12345678\nmov edx, 0x9ABCDEF0\nshld eax, edx, 4", None, 0x23456789),
    ("shrdimm", "mov eax, 0x12345678\nmov edx, 0x9ABCDEF0\nshrd eax, edx, 4", None, 0x01234567),
    ("shldcl", "mov eax, 0x12345678\nmov edx, 0x9ABCDEF0\nmov cl, 4\nshld eax, edx, cl", None, 0x23456789),
    # bsf/bsr
    ("bsfbsr", "mov eax, 0x10\nbsf edx, eax\nbsr ecx, eax\nadd edx, ecx\nmov eax, edx", None, 8),
    ("bsfzero", "xor eax, eax\nmov edx, 0x7A\nbsf edx, eax\nsetz al\nadd eax, edx", None, 0x7B),
    # popcnt / crc32
    ("popcnt32", "mov eax, 0x0F0F0F0F\npopcnt eax, eax", None, 16),
    ("popcnt64", "mov rax, 0x0F0F0F0F0F0F0F0F\npopcnt rax, rax", "", 32),
    ("crc32b", _CRC32B64, _CRC32B86, CRC32B_EXPECT),
    ("crc32q", _CRC32Q, "", CRC32Q_EXPECT),
    # xadd
    ("xadd", "mov eax, 2\nmov ebx, 3\nxadd eax, ebx\nadd eax, ebx", None, 7),
    # lahf / sahf
    ("lahf", "xor eax, eax\nlahf\nshr eax, 8", None, 0x46),
    ("sahf", "mov ah, 0x81\nsahf\npushfq\npop rax\nmovzx eax, al",
             "mov ah, 0x81\nsahf\npushfd\npop eax\nmovzx eax, al", 0x81 | 2),
    # segment moves read a flat zero selector
    ("segread", "mov rax, fs", "mov eax, fs", 0),
    # scas: single compare flags + rdi step
    ("scasb_match", "mov byte ptr [rsp+8], 0x77\nlea rdi, [rsp+8]\nmov al, 0x77\nscasb\nsete bl\nmovzx eax, bl",
                    "mov byte ptr [esp+8], 0x77\nlea edi, [esp+8]\nmov al, 0x77\nscasb\nsete bl\nmovzx eax, bl", 1),
    ("repne_scas_finds",
        "xor eax, eax\nmov rdi, rsp\nmov rcx, 8\nrep stosb\nmov byte ptr [rsp+2], 0x77\n"
        "mov al, 0x77\nmov rdi, rsp\nmov rcx, 4\nrepne scasb\nmov eax, 6\nsub eax, ecx",
        "xor eax, eax\nmov edi, esp\nmov ecx, 8\nrep stosb\nmov byte ptr [esp+2], 0x77\n"
        "mov al, 0x77\nmov edi, esp\nmov ecx, 4\nrepne scasb\nmov eax, 6\nsub eax, ecx", 5),
    ("repne_scas_notfound",
        "xor eax, eax\nmov rdi, rsp\nmov rcx, 8\nrep stosb\nmov al, 0x11\nmov rcx, 4\nrepne scasb\nmov eax, ecx",
        "xor eax, eax\nmov edi, esp\nmov ecx, 8\nrep stosb\nmov al, 0x11\nmov ecx, 4\nrepne scasb\nmov eax, ecx", 0),
    # ret with stack-discard imm: epilogue alignment must survive
    ("retimm",
        "push rcx\npush rcx\ncall T\nnop\nmov eax, 0x55\njmp Q\nT: ret 16\nQ:",
        "push ecx\npush ecx\ncall T\nnop\nmov eax, 0x55\njmp Q\nT: ret 8\nQ:", 0x55),
]

CRC32B_EXPECT = _crc32c_intel(0, struct.pack("<B", 0x31))
CRC32Q_EXPECT = _crc32c_intel(0, struct.pack("<Q", 0x1122334455667788))


def test_cases(tmp_path):
    for name, asm64, asm86, expect in CASES:
        _run_case(name, asm64, asm86, expect, tmp_path)


def test_nop_forms(tmp_path):
    # int3, nop r/m (0F 1F /r), nop [mem], endbr32/endbr64: all no-ops here
    body = (b"\xCC"                      # int3
            b"\x0F\x1F\xCA"              # nop rdx
            b"\x0F\x1F\x40\x00"          # nop dword ptr [rax]
            b"\xF3\x0F\x1E\xFA\xF3\x0F\x1E\xFB")  # endbr32 endbr64
    for is64 in (True, False):
        b = _blob_raw(body, is64)
        code, err = _exit_code(b, is64, tmp_path)
        assert code == 0x55, f"nop forms [{'x64' if is64 else 'x86'}]: exit {code:#x}\n{err[-800:]}"


def _blob_raw(asm_bytes, is64):
    ks = (Ks(_ks.KS_ARCH_X86, _ks.KS_MODE_64) if is64 else Ks(_ks.KS_ARCH_X86, _ks.KS_MODE_32))
    pro, _ = ks.asm(PRO64 if is64 else PRO86)
    tail_asm = "mov eax, 0x55\nhlt\n"
    tail, _ = ks.asm(tail_asm)
    return bytes(pro) + asm_bytes + bytes(tail)


def test_pause(tmp_path):
    for is64 in (True, False):
        code, err = _exit_code(_blob("mov eax, 0x55\npause", is64), is64, tmp_path)
        assert code == 0x55, f"pause [{'x64' if is64 else 'x86'}]: exit {code:#x}\n{err[-800:]}"
