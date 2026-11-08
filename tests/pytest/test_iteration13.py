import conftest
import re

# Iteration 13: x87 value tests (batch C of "all user-mode opcodes").
#
# Same contract as iterations 11/12: a keystone-assembled blob runs the
# body, writes its result into EAX and halts (exit code = EAX). Expected
# values are real-x87 semantics; float constants are IEEE-754 bits.

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
    # asm86 None = same asm on both (r-named registers auto-converted);
    # asm86 "" = x64-only
    asm86_fallback = _x86asm(asm64) if asm86 is None else asm86
    for is64, asm in ((True, asm64), (False, asm86_fallback)):
        if asm is None:
            continue
        expect_ = (expect[0] if is64 else expect[1]) if isinstance(expect, tuple) else expect
        try:
            b = _blob(asm, is64)
        except KsError as e:
            raise AssertionError(f"{name} [{'x64' if is64 else 'x86'}] failed to assemble: {e}")
        code, err = _exit_code(b, is64, tmp_path, name.replace("/", "_").replace(",", "_"))
        assert code == expect_, f"{name} [{'x64' if is64 else 'x86'}]: exit {code:#x} != {expect_:#x}\n{err[-800:]}"


CASES = [
    # --- data movement ---
    ("fld_fstp_m64", "mov dword ptr [rsp], 0x00000000\nmov dword ptr [rsp+4], 0x3FF00000\n"
                     "fld qword ptr [rsp]\nfstp qword ptr [rsp+8]\nmov eax, dword ptr [rsp+12]",
     None, 0x3FF00000),
    ("fld_m32", "mov dword ptr [rsp], 0x40400000\nfld dword ptr [rsp]\nfstp dword ptr [rsp+8]\nmov eax, dword ptr [rsp+8]",
     None, 0x40400000),
    # --- register arithmetic on the stack ---
    ("faddp", "mov dword ptr [rsp], 0\nmov dword ptr [rsp+4], 0x40200000\n"      # 8.0
              "mov dword ptr [rsp+8], 0\nmov dword ptr [rsp+12], 0x3FF00000\n"   # 1.0
              "fld qword ptr [rsp]\nfld qword ptr [rsp+8]\nfaddp\n"
              "fstp qword ptr [rsp+16]\nmov eax, dword ptr [rsp+20]",              # 9.0
     None, 0x40220000),
    ("fmul_mem", "mov dword ptr [rsp], 0x40400000\nfld dword ptr [rsp]\n"         # 3.0
                 "mov dword ptr [rsp+8], 0x40000000\nfmul dword ptr [rsp+8]\n"     # *2.0
                 "fstp dword ptr [rsp+12]\nmov eax, dword ptr [rsp+12]",             # 6.0
     None, 0x40C00000),
    ("fsub_mem", "mov dword ptr [rsp], 0\nmov dword ptr [rsp+4], 0x40240000\n"    # 10.0
                 "mov dword ptr [rsp+8], 0\nmov dword ptr [rsp+12], 0x40100000\n" # 4.0
                 "fld qword ptr [rsp]\nfsub qword ptr [rsp+8]\n"
                 "fstp qword ptr [rsp+16]\nmov eax, dword ptr [rsp+20]",             # 6.0
     None, 0x40180000),
    ("fdiv_mem", "mov dword ptr [rsp], 0\nmov dword ptr [rsp+4], 0x40200000\n"    # 8.0
                 "mov dword ptr [rsp+8], 0\nmov dword ptr [rsp+12], 0x40000000\n" # 2.0
                 "fld qword ptr [rsp]\nfdiv qword ptr [rsp+8]\n"
                 "fstp qword ptr [rsp+16]\nmov eax, dword ptr [rsp+20]",             # 4.0
     None, 0x40100000),
    ("fsubr_mem", "mov dword ptr [rsp], 0\nmov dword ptr [rsp+4], 0x40200000\n"   # 8.0
                  "mov dword ptr [rsp+8], 0\nmov dword ptr [rsp+12], 0x40080000\n" # 3.0
                  "fld qword ptr [rsp]\nfsubr qword ptr [rsp+8]\n"                  # 3 - 8 = -5
                  "fstp qword ptr [rsp+16]\nmov eax, dword ptr [rsp+20]",
     None, 0xC0140000),
    ("fsubp", "mov dword ptr [rsp], 0\nmov dword ptr [rsp+4], 0x40000000\n"      # 2.0
              "mov dword ptr [rsp+8], 0\nmov dword ptr [rsp+12], 0x40240000\n"   # 10.0
              "fld qword ptr [rsp]\nfld qword ptr [rsp+8]\n"                     # st0=10, st1=2
              "fsubp\n"                                                          # st1 = 2 - 10 = -8, pop
              "fstp qword ptr [rsp+16]\nmov eax, dword ptr [rsp+20]",
     None, 0xC0200000),
    # --- integer conversions ---
    ("fild_fistp", "mov dword ptr [rsp], 0x1234\nfild dword ptr [rsp]\n"
                   "fistp dword ptr [rsp+8]\nmov eax, dword ptr [rsp+8]",
     None, 0x1234),
    ("fistp_neg", "mov dword ptr [rsp], 0xFFFFFFF9\nfild dword ptr [rsp]\n"
                  "fistp dword ptr [rsp+8]\nmov eax, dword ptr [rsp+8]",
     None, 0xFFFFFFF9),
    ("fildq_fistpq", "mov dword ptr [rsp], 0x23456789\nmov dword ptr [rsp+4], 1\n"
                     "fild qword ptr [rsp]\nfistp qword ptr [rsp+8]\nmov eax, dword ptr [rsp+12]",
     None, 1),
    # --- compares / flags ---
    ("fcom_gt", "fld1\nfldz\nfcom\nfnstsw ax\nmovzx eax, ax\nand eax, 0x4500",
     None, 0x0100),
    ("fcom_eq", "fld1\nfld1\nfcom\nfnstsw ax\nmovzx eax, ax\nand eax, 0x4500",
     None, 0x4000),
    ("fcom_unordered", "fld1\nmov dword ptr [rsp], 1\nmov dword ptr [rsp+4], 0x7FF00000\n"
                       "fld qword ptr [rsp]\nfcom\nfnstsw ax\nmovzx eax, ax\nand eax, 0x4500",
     None, 0x4500),
    ("fucomip_branch", "mov dword ptr [rsp], 0\nmov dword ptr [rsp+4], 0x40140000\n"  # 5.0
                       "fld qword ptr [rsp]\nfld1\n"                                   # st0=1, st1=5
                       "fucomi st(1)\njb M1\nmov eax, 2\njmp M2\nM1:\nmov eax, 1\nM2:\n"
                       "fstp st",
     None, 1),  # 1 < 5 -> CF -> jb taken
    ("fcmovb_taken", "mov dword ptr [rsp], 0\nmov dword ptr [rsp+4], 0x40140000\n"  # 5.0
                     "fld qword ptr [rsp]\nfld1\n"                                   # st0=1, st1=5
                     "fucomi st(1)\nfcmovb st, st(1)\n"                              # 1 < 5 -> st0 = 5
                     "fistp dword ptr [rsp+16]\nmov eax, dword ptr [rsp+16]",
     None, 5),
    ("fcompp_flags", "mov dword ptr [rsp], 0\nmov dword ptr [rsp+4], 0x40140000\n"  # 5.0
                     "fld qword ptr [rsp]\nmov dword ptr [rsp+8], 0\nmov dword ptr [rsp+12], 0x40080000\n"  # 3.0
                     "fld qword ptr [rsp+8]\nfcompp\nfnstsw ax\nmovzx eax, ax\nand eax, 0x4500",
     None, 0x0100),  # 3 < 5
    # --- transcendentals / reductions (exact-input cases only) ---
    ("fsqrt", "mov dword ptr [rsp], 0\nmov dword ptr [rsp+4], 0x40220000\n"      # 9.0
              "fld qword ptr [rsp]\nfsqrt\nfstp qword ptr [rsp+8]\nmov eax, dword ptr [rsp+12]",  # 3.0
     None, 0x40080000),
    ("frndint", "mov dword ptr [rsp], 0\nmov dword ptr [rsp+4], 0x400C0000\n"    # 3.5
                "fld qword ptr [rsp]\nfrndint\nfstp qword ptr [rsp+8]\nmov eax, dword ptr [rsp+12]",  # 4.0 (RNE)
     None, 0x40100000),
    ("fprem", "mov dword ptr [rsp], 0\nmov dword ptr [rsp+4], 0x401C0000\n"      # 7.0
              "mov dword ptr [rsp+8], 0\nmov dword ptr [rsp+12], 0x40000000\n"   # 2.0
              "fld qword ptr [rsp]\nfld qword ptr [rsp+8]\nfprem\n"              # st0=2, st1=7: 2 mod 7 = 2
              "fstp qword ptr [rsp+16]\nmov eax, dword ptr [rsp+20]",             # remainder 2.0
     None, 0x40000000),
    ("fchs", "mov dword ptr [rsp], 0\nmov dword ptr [rsp+4], 0x40000000\n"      # 2.0
             "fld qword ptr [rsp]\nfchs\nfstp qword ptr [rsp+8]\nmov eax, dword ptr [rsp+12]",  # -2.0
     None, 0xC0000000),
    ("fabs", "mov dword ptr [rsp], 0\nmov dword ptr [rsp+4], 0xC0000000\n"      # -2.0
             "fld qword ptr [rsp]\nfabs\nfstp qword ptr [rsp+8]\nmov eax, dword ptr [rsp+12]",  # 2.0
     None, 0x40000000),
    ("fxch", "mov dword ptr [rsp], 0\nmov dword ptr [rsp+4], 0x40080000\n"      # 3.0
             "mov dword ptr [rsp+8], 0\nmov dword ptr [rsp+12], 0x40A00000\n"   # 5.0
             "fld qword ptr [rsp]\nfld qword ptr [rsp+8]\n"                      # st0=5, st1=3
             "fxch\nfstp qword ptr [rsp+16]\nmov eax, dword ptr [rsp+20]",        # pop st0 = 3
     None, 0x40080000),
    ("fdecstp", "fldz\nfdecstp\nfnstsw ax\nmovzx eax, ax\nand eax, 0x3800",
     None, 0x3000),  # top 7 -> 6
    ("f2xm1_zero", "fldz\nf2xm1\nfstp qword ptr [rsp]\nmov eax, dword ptr [rsp+4]",
     None, 0),
    ("fyl2x", "mov dword ptr [rsp], 0\nmov dword ptr [rsp+4], 0x40080000\n"     # 3.0 -> st1
              "mov dword ptr [rsp+8], 0\nmov dword ptr [rsp+12], 0x40000000\n"  # 2.0 -> st0
              "fld qword ptr [rsp]\nfld qword ptr [rsp+8]\nfyl2x\n"             # 3*log2(2) = 3
              "fstp qword ptr [rsp+16]\nmov eax, dword ptr [rsp+20]",
     None, 0x40080000),
    ("fpatan_zero", "fldz\nfld1\nfpatan\n"                                       # atan(0/1) = 0
                    "fstp qword ptr [rsp]\nmov eax, dword ptr [rsp+4]",
     None, 0),
    ("fsincos_zero", "fldz\nfsincos\n"                                           # st0=cos 1, st1=sin 0
                     "fstp qword ptr [rsp]\nmov eax, dword ptr [rsp+4]",          # cos(0) = 1.0 (high dword)
     None, 0x3FF00000),
    ("fscale", "mov dword ptr [rsp], 0\nmov dword ptr [rsp+4], 0x40080000\n"     # 3.0 -> st1
               "mov dword ptr [rsp+8], 0\nmov dword ptr [rsp+12], 0x40000000\n"  # 2.0 -> st0
               "fld qword ptr [rsp]\nfld qword ptr [rsp+8]\nfscale\n"            # 2 * 2^3 = 16
               "fstp qword ptr [rsp+16]\nmov eax, dword ptr [rsp+20]",
     None, 0x40300000),
    ("fcos_zero", "fldz\nfcos\nfstp qword ptr [rsp]\nmov eax, dword ptr [rsp+4]",
     None, 0x3FF00000),
    ("fptan_zero", "fldz\nfptan\n"                                               # st0=1 pushed, st1=tan(0)=0
                   "fstp qword ptr [rsp]\nfstp qword ptr [rsp+8]\n"
                   "mov eax, dword ptr [rsp+12]",                                  # tan(0) = 0
     None, 0),
    ("fyl2xp1", "mov dword ptr [rsp], 0\nmov dword ptr [rsp+4], 0x40080000\n"    # 3.0 -> st1
                "mov dword ptr [rsp+8], 0\nmov dword ptr [rsp+12], 0x3FF00000\n"  # 1.0 -> st0
                "fld qword ptr [rsp]\nfld qword ptr [rsp+8]\nfyl2xp1\n"           # 3*log2(2) = 3
                "fstp qword ptr [rsp+16]\nmov eax, dword ptr [rsp+20]",
     None, 0x40080000),
    # --- control / status words ---
    ("fldcw_fnstcw", "mov word ptr [rsp+8], 0x0F7F\nfldcw word ptr [rsp+8]\n"
                     "fnstcw word ptr [rsp+16]\nmovzx eax, word ptr [rsp+16]\nand eax, 0x037F",
     None, 0x037F),
    ("fnstsw_top", "fldz\nfldz\nfldz\nfnstsw ax\n"                                  # top 0 -> (init -3) = 5
                   "movzx eax, ax\nshr eax, 11\nand eax, 7",
     None, 5),
]


def test_fcmovb_not_taken(tmp_path):
    # 9 vs 3: fucomi sets CF=0 (not below), fcmovb must leave st0 = 3
    asm = ("mov dword ptr [rsp], 0\nmov dword ptr [rsp+4], 0x40220000\n"  # 9.0
           "mov dword ptr [rsp+8], 0\nmov dword ptr [rsp+12], 0x40080000\n"  # 3.0
           "fld qword ptr [rsp]\nfld qword ptr [rsp+8]\n"  # st0=3, st1=9... 3 < 9 -> taken
           "fucomi st(1)\n")
    # not-taken direction: st0 = 9, st1 = 3
    asm = ("mov dword ptr [rsp], 0\nmov dword ptr [rsp+4], 0x40080000\n"  # 3.0 loaded first
           "mov dword ptr [rsp+8], 0\nmov dword ptr [rsp+12], 0x40220000\n"  # 9.0
           "fld qword ptr [rsp]\nfld qword ptr [rsp+8]\n"  # st0=9, st1=3
           "fucomi st(1)\nfcmovb st, st(1)\n"  # 9 !< 3 -> no move
           "fistp dword ptr [rsp+16]\nmov eax, dword ptr [rsp+16]")
    code, err = _exit_code(_blob(asm, True), True, tmp_path, "fcmovb_not")
    assert code == 9, f"fcmovb_not_taken: exit {code:#x}\n{err[-800:]}"  # 9 stays (float 3.0 would trap to 3)


def test_cases(tmp_path):
    for name, asm64, asm86, expect in CASES:
        _run_case(name, asm64, asm86, expect, tmp_path)
