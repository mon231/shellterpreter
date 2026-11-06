import conftest

# Iteration 12: SSE/SSE2 value tests (batch B of "all user-mode opcodes").
#
# Same contract as iteration 11: a keystone-assembled blob runs the body,
# writes its result into EAX and halts (exit code = EAX). Expected values
# are real-x86 semantics; float constants are embedded as IEEE-754 bits.

from keystone import Ks, KsError
import keystone as _ks

PRO64 = "sub rsp, 0x40\ncld\n"
PRO86 = "sub esp, 0x40\ncld\n"


def _blob(asm, is64):
    ks = Ks(_ks.KS_ARCH_X86, _ks.KS_MODE_64) if is64 else Ks(_ks.KS_ARCH_X86, _ks.KS_MODE_32)
    pro, _ = ks.asm(PRO64 if is64 else PRO86)
    body, _ = ks.asm(asm)
    tail, _ = ks.asm("hlt\n")
    return bytes(pro) + bytes(body) + bytes(tail)


def _exit_code(blobbytes, is64, tmp_path, tag):
    exe = conftest.X64_DIR if is64 else conftest.X86_DIR
    p = (tmp_path / tag).with_suffix(".shellcode")
    p.write_bytes(blobbytes)
    r = conftest.run([str(exe / "shellterpreter.exe"), str(p)])
    rc = r.returncode
    code = conftest.win_code(rc) if rc < 0 else (rc & 0xFFFFFFFF)
    return code, r.stderr


import re

_X86REG = {"rax": "eax", "rbx": "ebx", "rcx": "ecx", "rdx": "edx",
           "rsi": "esi", "rdi": "edi", "rbp": "ebp", "rsp": "esp"}


def _x86asm(asm):
    def sub_register(m):
        return _X86REG[m.group(0)]
    return re.sub(r"\b(rax|rbx|rcx|rdx|rsi|rdi|rbp|rsp)\b", sub_register, asm)


def _run_case(name, asm64, asm86, expect, tmp_path):
    # asm86 None = same asm on both (r-named registers auto-converted);
    # asm86 "" = x64-only
    if asm86 is None and any(f"r{k}" in asm64.split() or any(r in asm64 for r in _X86REG) for k in ()):
        asm86_fallback = _x86asm(asm64)
    else:
        asm86_fallback = _x86asm(asm64) if asm86 is None else asm86
    for is64, asm in ((True, asm64), (False, asm86_fallback if (asm86_fallback is not None and asm86_fallback != "") else (None if asm86_fallback == "" else asm64))):
        if asm is None:
            continue
        expect_ = (expect[0] if is64 else expect[1]) if isinstance(expect, tuple) else expect
        try:
            b = _blob(asm, is64)
        except KsError as e:
            raise AssertionError(f"{name} [{'x64' if is64 else 'x86'}] failed to assemble: {e}")
        code, err = _exit_code(b, is64, tmp_path, name.replace("/", "_").replace(",", "_"))
        assert code == expect_, f"{name} [{'x64' if is64 else 'x86'}]: exit {code:#x} != {expect_:#x}\n{err[-800:]}"


ALL32 = 0xFFFFFFFF

CASES = [
    # --- scalar arithmetic (3.0 op 2.0 = 5.0 / 6.0 / 1.0 / 1.5) ---
    ("addss", "mov dword ptr [rsp], 0x40400000\nmovss xmm0, [rsp]\n"
              "mov dword ptr [rsp+4], 0x40000000\nmovss xmm1, [rsp+4]\n"
              "addss xmm0, xmm1\nmovss dword ptr [rsp+8], xmm0\nmov eax, dword ptr [rsp+8]", None,
              0x40A00000),
    ("mulss", "mov dword ptr [rsp], 0x40400000\nmovss xmm0, [rsp]\n"
              "mov dword ptr [rsp+4], 0x40000000\nmovss xmm1, [rsp+4]\n"
              "mulss xmm0, xmm1\nmovss dword ptr [rsp+8], xmm0\nmov eax, dword ptr [rsp+8]", None,
              0x40C00000),
    ("subss", "mov dword ptr [rsp], 0x40400000\nmovss xmm0, [rsp]\n"
              "mov dword ptr [rsp+4], 0x40000000\nmovss xmm1, [rsp+4]\n"
              "subss xmm0, xmm1\nmovss dword ptr [rsp+8], xmm0\nmov eax, dword ptr [rsp+8]", None,
              0x3F800000),
    ("divss", "mov dword ptr [rsp], 0x40400000\nmovss xmm0, [rsp]\n"
              "mov dword ptr [rsp+4], 0x40000000\nmovss xmm1, [rsp+4]\n"
              "divss xmm0, xmm1\nmovss dword ptr [rsp+8], xmm0\nmov eax, dword ptr [rsp+8]", None,
              0x3FC00000),
    # --- packed: [3.0,5.0] + [1.0,2.0] = [4.0,7.0] ---
    ("addps_lo", "mov dword ptr [rsp], 0x40400000\nmov dword ptr [rsp+4], 0x40A00000\n"
                 "mov dword ptr [rsp+8], 0x3F800000\nmov dword ptr [rsp+12], 0x40000000\n"
                 "movups xmm0, [rsp]\nmovups xmm1, [rsp+8]\naddps xmm0, xmm1\n"
                 "movups [rsp+16], xmm0\nmov eax, dword ptr [rsp+16]", None,
                 0x40800000),
    ("addps_hi", "mov dword ptr [rsp], 0x40400000\nmov dword ptr [rsp+4], 0x40A00000\n"
                 "mov dword ptr [rsp+8], 0x3F800000\nmov dword ptr [rsp+12], 0x40000000\n"
                 "movups xmm0, [rsp]\nmovups xmm1, [rsp+8]\naddps xmm0, xmm1\n"
                 "movups [rsp+16], xmm0\nmov eax, dword ptr [rsp+20]", None,
                 0x40E00000),
    ("sqrtss", "mov dword ptr [rsp], 0x40800000\nmovss xmm0, [rsp]\n"
               "sqrtss xmm0, xmm0\nmovss dword ptr [rsp+4], xmm0\nmov eax, dword ptr [rsp+4]", None,
               0x40000000),
    # --- conversions ---
    ("cvtss2sd", "mov dword ptr [rsp], 0x3F800000\nmovss xmm0, [rsp]\n"
                 "cvtss2sd xmm1, xmm0\nmovq qword ptr [rsp+8], xmm1\nmov eax, dword ptr [rsp+12]", None,
                 0x3FF00000),  # hi dword of double 1.0
    ("cvtsi2ss", "mov eax, 5\ncvtsi2ss xmm0, eax\nmovss dword ptr [rsp], xmm0\nmov eax, dword ptr [rsp]", None,
                 0x40A00000),  # 5.0f
    ("cvtsi2sd", "mov rax, 5\ncvtsi2sd xmm0, rax\nmovq qword ptr [rsp], xmm0\nmov eax, dword ptr [rsp+4]",
                 "mov eax, 5\ncvtsi2sd xmm0, eax\nmovq qword ptr [esp], xmm0\nmov eax, dword ptr [esp+4]",
                 0x40140000),  # hi dword of double 5.0
    ("cvttsd2si", "mov dword ptr [rsp], 0x00000000\nmov dword ptr [rsp+4], 0x40060000\n"  # 2.75 double
                  "movq xmm0, qword ptr [rsp]\ncvttsd2si eax, xmm0", None,
                  2),
    ("cvttsd2si_range", "mov dword ptr [rsp], 0x20000000\nmov dword ptr [rsp+4], 0x4202A05F\n"  # 1e10 double
                        "movq xmm0, qword ptr [rsp]\ncvttsd2si eax, xmm0", None,
                        0x80000000),  # integer indefinite
    # --- data movement ---
    ("movd_rt", "mov eax, 0xDEADBEEF\nmovd xmm0, eax\nmovd ecx, xmm0\nmov eax, ecx",
                None, 0xDEADBEEF),
    ("cmpeqss", "mov dword ptr [rsp], 0x40400000\nmovss xmm0, [rsp]\nmovss xmm1, [rsp]\n"
                "cmpss xmm0, xmm1, 0\nmovd eax, xmm0",
                None, ALL32),
    ("cmpneqss_true", "mov dword ptr [rsp], 0x40400000\nmovss xmm0, [rsp]\n"
                      "mov dword ptr [rsp+4], 0x40800000\nmovss xmm1, [rsp+4]\n"
                      "cmpss xmm0, xmm1, 4\nmovd eax, xmm0",
                      None, ALL32),  # neq: 3.0 != 4.0
    ("pslld", "mov dword ptr [rsp], 0xF0000011\nmovd xmm0, dword ptr [rsp]\npslld xmm0, 4\n"
              "movd eax, xmm0",
              None, 0x00000110),
    # --- insert / extract ---
    ("pinsrw_pextrw", "mov eax, 0x1234\npinsrw xmm0, eax, 1\npextrw eax, xmm0, 1",
                     None, 0x1234),
    ("pinsrd_pextrd", "mov eax, 0xABCD1234\npinsrd xmm0, eax, 2\npextrd ecx, xmm0, 2\nmov eax, ecx",
                     None, 0xABCD1234),
    ("pinsrb_pextrb", "mov eax, 0x5A\npinsrb xmm0, eax, 9\npextrb ecx, xmm0, 9\nmov eax, ecx",
                     None, 0x5A),
    # --- shuffle / move-lane ---
    ("shufps_lo", "mov dword ptr [rsp], 0x1\nmov dword ptr [rsp+4], 0x2\n"
                  "mov dword ptr [rsp+8], 0x3\nmov dword ptr [rsp+12], 0x4\n"
                  "mov dword ptr [rsp+16], 0x5\nmov dword ptr [rsp+20], 0x6\n"
                  "mov dword ptr [rsp+24], 0x7\nmov dword ptr [rsp+28], 0x8\n"
                  "movups xmm0, [rsp]\nmovups xmm1, [rsp+16]\n"
                  "shufps xmm0, xmm1, 0x18\n"  # [src0, src2, dst1, dst0] = [5,7,2,1]
                  "movups [rsp+32], xmm0\nmov eax, dword ptr [rsp+32]",
                  None, 5),
    ("shufps_hi", "mov dword ptr [rsp], 0x1\nmov dword ptr [rsp+4], 0x2\n"
                  "mov dword ptr [rsp+8], 0x3\nmov dword ptr [rsp+12], 0x4\n"
                  "mov dword ptr [rsp+16], 0x5\nmov dword ptr [rsp+20], 0x6\n"
                  "mov dword ptr [rsp+24], 0x7\nmov dword ptr [rsp+28], 0x8\n"
                  "movups xmm0, [rsp]\nmovups xmm1, [rsp+16]\n"
                  "shufps xmm0, xmm1, 0x18\n"
                  "movups [rsp+32], xmm0\nmov eax, dword ptr [rsp+36]",
                  None, 7),
    ("movhlps", "mov dword ptr [rsp], 0x1\nmov dword ptr [rsp+4], 0x2\n"
                "mov dword ptr [rsp+8], 0x3\nmov dword ptr [rsp+12], 0x4\n"
                "mov dword ptr [rsp+16], 0x5\nmov dword ptr [rsp+20], 0x6\n"
                "movups xmm0, [rsp]\nmovups xmm1, [rsp+8]\n"
                "movhlps xmm0, xmm1\nmovd eax, xmm0",
                None, 5),  # xmm0 low qword = xmm1 high qword = [5,6]
    ("pshufd", "mov dword ptr [rsp], 0x1\nmov dword ptr [rsp+4], 0x2\n"
               "mov dword ptr [rsp+8], 0x3\nmov dword ptr [rsp+12], 0x4\n"
               "movups xmm0, [rsp]\npshufd xmm1, xmm0, 0x1B\n"  # reverse -> [4,3,2,1]
               "movd eax, xmm1",
               None, 4),
    # --- p-shifts; qword lanes shift independently ---
    ("psrlq_mmx", "mov dword ptr [rsp], 0x02000000\nmov dword ptr [rsp+4], 1\n"
                  "movq mm0, qword ptr [rsp]\npsrlq mm0, 8\n"
                  "movq qword ptr [rsp+8], mm0\nmov eax, dword ptr [rsp+8]",
                  None, 0x01020000),
    ("psrlq_xmm", "mov dword ptr [rsp], 0x02000000\nmov dword ptr [rsp+4], 1\n"
                  "movq xmm0, qword ptr [rsp]\npsrlq xmm0, 8\n"
                  "movq qword ptr [rsp+8], xmm0\nmov eax, dword ptr [rsp+8]",
                  None, 0x01020000),
    # --- mmx add + emms ---
    ("paddd_mmx", "mov dword ptr [rsp], 0x22222222\nmov dword ptr [rsp+4], 0x11111111\n"
                  "movq mm0, qword ptr [rsp]\npaddd mm0, mm0\n"
                  "movq qword ptr [rsp+8], mm0\nmov eax, dword ptr [rsp+8]",
                  None, 0x44444444),
    ("emms", "pxor xmm0, xmm0\ncvtdq2pd xmm0, xmm0\nemms\npxor xmm2, xmm2\nmovd eax, xmm2",
             None, 0),
    ("pxor_idiom", "mov dword ptr [rsp], 0x11223344\nmovd xmm0, dword ptr [rsp]\n"
                   "pxor xmm0, xmm0\nmovd eax, xmm0",
                   None, 0),
]


def test_movq_roundtrip(tmp_path):
    # F3 0F 7E load + 66 0F D6 store, both archs; F2 movsd load merged low
    # dword check lives in the corpus; here the qword boundary matters.
    for is64, base in ((True, "r"), (False, "e")):
        asm = (f"mov dword ptr [{base}sp], 0x55667788\n"
               f"mov dword ptr [{base}sp+4], 0x11223344\n"
               f"movq xmm0, qword ptr [{base}sp]\n"
               f"movq qword ptr [{base}sp+8], xmm0\n"
               f"mov eax, dword ptr [{base}sp+8]")
        b = _blob(asm, is64)
        code, err = _exit_code(b, is64, tmp_path, f"movqrt{int(is64)}")
        assert code == 0x55667788, f"movq_rt [{'x64' if is64 else 'x86'}]: exit {code:#x}\n{err[-800:]}"


def test_cases(tmp_path):
    for name, asm64, asm86, expect in CASES:
        _run_case(name, asm64, asm86, expect, tmp_path)
