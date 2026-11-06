"""Dev tool (not part of the pytest suite): assembles a corpus of user-mode
instruction templates with keystone, wraps each into a tiny shellcode
(prologue + instruction + mov eax,0x55 + ret), runs it through the
interpreter, and reports the outcome per template.

Outcome classes:
  OK       exit 0x55: instruction decoded and executed
  UNSUP    fault 0xE0000001: not implemented
  MEMSHARE fault 0xE0000002: decoded with wrong length / bad access
  OTHER    exit != 0x55 with no fault: executed, but state diverged
  ASMERR   keystone could not assemble / invalid form for the arch

Usage: python _opcode_corpus.py [x64|x86|all]
"""
import conftest
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

from keystone import Ks, KsError

import keystone as _ks

KS64 = _ks.Ks(_ks.KS_ARCH_X86, _ks.KS_MODE_64)
KS32 = _ks.Ks(_ks.KS_ARCH_X86, _ks.KS_MODE_32)
EAX_OK = 0x55

PRO64 = "sub rsp, 0x40\ncld\n"
PRO86 = "sub esp, 0x40\ncld\n"
EPI64 = "add rsp, 0x40\nmov eax, 0x55\nret\n"
EPI86 = "add esp, 0x40\nmov eax, 0x55\nret\n"
PRO, EPI = PRO64, EPI64


def blob(asm, mode):
    pro = PRO64 if mode == "x64" else PRO86
    epi = EPI64 if mode == "x64" else EPI86
    if isinstance(asm, bytes):
        ks = KS64 if mode == "x64" else KS32
        pro_enc, _ = ks.asm(pro)
        epi_enc, _ = ks.asm(epi)
        return bytes(pro_enc) + asm + bytes(epi_enc)
    full = pro + asm + "\n" + epi
    ks = KS64 if mode == "x64" else KS32
    try:
        enc, _ = ks.asm(full)
        if enc is None:
            return None
        return bytes(enc)
    except KsError:
        return None


def run(exe, data):
    p = Path(tempfile.gettempdir()) / "opprobe.shellcode"
    p.write_bytes(data)
    r = subprocess.run([str(exe), str(p)], capture_output=True, text=True, timeout=20)
    rc = r.returncode
    return conftest.win_code(rc) if rc < 0 else (rc & 0xFFFFFFFF), r.stderr


def classify(rc):
    if rc == EAX_OK:
        return "OK"
    if rc == 0xE0000001:
        return "UNSUP"
    if rc == 0xE0000002:
        return "MEMSHARE"
    return "OTHER"


# --- corpus templates -------------------------------------------------------
# Each: (name, x64 asm or None, x86 asm or None, optional per-arch prologue
# lines injected before the instruction). Registers start mostly zeroed.

R64 = ["rax", "rcx", "rdx", "rbx", "rsi", "rdi", "rbp", "r8"]
R32 = ["eax", "ecx", "edx", "ebx", "esi", "edi", "ebp"]

T = []  # (name, x64, x86)

def add(name, x64, x86=None):
    # asm may be a str (keystone) or bytes (manual encoding; blob() passes it through)
    T.append((name, x64, x86))

def add_both(name, asm):
    add(name, asm, asm)

# ALU reg,reg matrix (one pair per op x64; r8 mixed in for REX coverage)
for op in ["add", "or", "adc", "sbb", "and", "sub", "xor", "cmp"]:
    add(f"{op} rax,rbx", f"{op} rax, rbx", f"{op} eax, ebx")
    add(f"{op} r8,rbx", f"{op} r8, rbx", None)
add("alu mem", "add qword ptr [rsp], rax", "add dword ptr [esp], eax")

# imm forms
add("add rax,imm32", "add rax, 0x1234", "add eax, 0x1234")
add("add r8,imm8", "add r8b, 2", "add bl, 2")
add("add [mem],imm", "add dword ptr [rsp], 3", "add dword ptr [esp], 3")

# inc/dec/neg/not/mul/div family
add("inc rax", "inc rax", "inc eax")
add("inc r8", "inc r8", None)
add("dec rbx", "dec rbx", "dec ebx")
add("inc [mem]", "inc qword ptr [rsp]", "inc dword ptr [esp]")
add("neg", "neg rax", "neg eax")
add("not", "not rax", "not eax")
add("mul", "mul rbx", "mul ebx")
add("imul r,r", "imul rax, rbx, 3", "imul eax, ebx, 3")
add("div", "mov rcx, 3\nmov rax, 9\ndiv rcx", "mov ecx, 3\nmov eax, 9\ndiv ecx")
add("idiv", "mov rcx, 3\nmov rax, 9\nidiv rcx", "mov ecx, 3\nmov eax, 9\nidiv ecx")
add("cwd/cdq", "cdq", "cwd")
add("cbw/cwde", "cwde", "cbw")

# test / cmp imm
add("test r,r", "test rax, rbx", "test eax, ebx")
add("test [mem],imm", "test dword ptr [rsp], 4", "test dword ptr [esp], 4")

# mov variants
add("mov r,r", "mov r9, rax", "mov edi, esi")
add("mov r,imm64", "mov rax, 0x1122334455667788", None)
add("movss mem", "mov qword ptr [rsp], rax", "mov dword ptr [esp], eax")
add("movzx/movsx reg", "movzx rax, r9b\nmovsx rax, r8w", "movzx eax, bh\nmovsx eax, cx")
add("movzx/movsx mem", "movzx r8, byte ptr [rsp]\nmovsx rax, word ptr [rsp+4]",
    "movzx eax, byte ptr [esp]\nmovsx eax, word ptr [esp+4]")
add("movsxd", "movsxd rdi, eax", None)

# shifts / rotates
for f in ["shl", "shr", "sar", "rol", "ror", "rcl", "rcr", "shld", "shrd"]:
    if f in ("shld", "shrd"):
        add(f, f"{f} rax, rdx, 3", f"{f} eax, edx, 3")
    else:
        add(f, f"{f} rax, 3", f"{f} eax, 3")
add("shift CL", "mov cl, 4\nshr rax, cl", "mov cl, 4\nshr eax, cl")
add("shift mem", "shr qword ptr [rsp], 3", "shr dword ptr [esp], 3")

# bit ops
add("bt/bts/btr/btc", "bt rax, 3\nbts rax, 5\nbtr rax, 1\nbtc rax, 7\nsetc cl", None)
add("bt mem", "bt qword ptr [rsp], 5", None)
add("bsf/bsr", "bsf rax, rbx\nbsr rdx, rbx", "bsf eax, ebx\nbsr edx, ebx")
add("bswap", "bswap rax", "bswap eax")
add("popcnt/crc32", "popcnt rax, rbx", None)
add("crc32b", "crc32 eax, r8b", None)

# exchange / atomic
add("xchg", "xchg rax, rbx", "xchg eax, ebx")
add("xchg reg,mem", "xchg rax, qword ptr [rsp]", "xchg eax, dword ptr [esp]")
add("cmpxchg", "cmpxchg rax, rbx", "cmpxchg eax, ebx")
add("xadd", "xadd rax, rbx", "xadd eax, ebx")
add("lock xadd", "lock xadd rax, rbx", "lock xadd eax, ebx")
add("lock cmpxchg", "mov rax, rbx\nlock cmpxchg rbx, rcx", None)

# pushes / pops / flags
add("push/pop", "push r9\npop rax", None)
add("push imm", "push 0x11\npop rax", "push 0x11\npop eax")
add("push fs / pop fs", "push fs\npop fs", "push fs\npop fs")
add("pushf/popf", "pushfq\npopfq", "pushfd\npopfd")
add("lahf/sahf", "lahf\nsahf", None)
add("cmc/clc/stc", "cmc\nclc\nstc", "cmc\nclc\nstc")
add("cli/sti", "cli\nsti", "cli\nsti")
add("cld/std", "cld\nstd\ncld", "cld\nstd\ncld")

# jumps / calls / setcc / cmovcc
add("jcc fwd/back", "test rax, rax\njz L\nnop\nL: nop", None)
add("jmp rel", "jmp L\nnop\nnop\nL:", None)
add("call/ret", "call L\nmov rax, rcx\njmp E\nL: xor rcx, rcx\nret\nE:",
    "call L\nmov eax, ecx\njmp E\nL: xor ecx, ecx\nret\nE:")
add("setcc", "xor rax, rax\nsete r8b", "xor eax, eax\nsete cl")
add("cmovcc", "cmovz rax, rbx", "cmovz eax, ebx")
add("loop", "mov rcx, 2\nL: loop L", "mov ecx, 2\nL: loop L")
add("jcxz", "jecxz L\nnop\nnop\nL:", None)
add("ret imm", "push rcx\npush rcx\ncall T\nnop\nmov eax, 0x55\njmp Q\nT: ret 16\nQ:",
    "push ecx\npush ecx\ncall T\nnop\nmov eax, 0x55\njmp Q\nT: ret 8\nQ:")

# string ops
add("movsb/d/sq", "mov rdi, rsp\nmov rsi, rsp\nmovsb\nmovsq\nmovs qword ptr [rdi], [rsi]", None)
add("stosd/stosb", "mov rdi, rsp\nstosd\nstosb", "mov edi, esp\nstosd\nstosb")
add("scasb/scasd", "mov rdi, rsp\nscasb\nscasd", "mov edi, esp\nscasb\nscasd")
add("lodsb", "mov rsi, rsp\nlodsb", "mov esi, esp\nlodsb")
add("rep movsb", "mov rdi, rsp\nmov rsi, rsp\nmov rcx, 4\nrep movsb", "mov edi, esp\nmov esi, esp\nmov ecx, 4\nrep movsb")
add("rep stosb", "mov rdi, rsp\nmov rcx, 3\nrep stosb", "mov edi, esp\nmov ecx, 3\nrep stosb")
add("repe cmpsb", "mov rdi, rsp\nmov rsi, rsp\nmov rcx, 4\nrepe cmpsb", "mov edi, esp\nmov esi, esp\nmov ecx, 4\nrepe cmpsb")
add("repne scasb", "mov rdi, rsp\nmov al, 0\nmov rcx, 4\nrepne scasb", "mov edi, esp\nmov al, 0\nmov ecx, 4\nrepne scasb")

# xchg / no-op variants
add("nop multi", "nop\nxchg eax, eax\npause", None)
add("int3", b"\xCC", None)
add("endbr32/endbr64", b"\xF3\x0F\x1E\xFA\xF3\x0F\x1E\xFB", None)
add("nop reg", b"\x0F\x1F\xCA", None)  # nop rdx (keystone maps nop [mem] to 0F 18)
add(".longitude", b"\x0F\x1F\x40\x00", None)  # nop dword ptr [rax]

# segment register moves (user-visible reads)
add("mov r, seg", "mov rax, fs\nmov rax, ds", "mov eax, fs\nmov eax, ds")
add("mov seg,r", "mov fs, rax", "mov fs, eax")
add("mov eax, cs", "mov rax, cs", "mov eax, cs")

# modrm: RIP-relative + SIB matrix (x64); absolute disp + SIB (x86)
add("rip rel", "mov rax, qword ptr [rip - 8]", None)
add("sib r8+x2+disp", "lea rax, qword ptr [r8 + rax*2 + 0x28]", "lea eax, dword ptr [ebx + eax*2 + 0x28]")
add("sib base none", "lea rax, qword ptr [rax*2 + 0x10]", "lea eax, dword ptr [eax*2 + 0x10]")
add("sib 9 combos", "lea rax, [rsp]\nlea rbx, [rsp+rax]")

# x87 core (D8-DF)
add("fld/fstp mem", "fld dword ptr [rsp]\nfstp dword ptr [rsp]", "fld dword ptr [esp]\nfstp dword ptr [esp]")
add("fild/fistp", "fild qword ptr [rsp]\nfistp qword ptr [rsp]", None)
add("fadd/fmul mem", "fld dword ptr [rsp]\nfadd dword ptr [rsp]\nfmul dword ptr [rsp]\nfstp dword ptr [rsp]", None)
add("fsub/fdiv mem", "fld dword ptr [rsp]\nfsub dword ptr [rsp]\nfdiv dword ptr [rsp]\nfstp dword ptr [rsp]", None)
add("faddp/fmulp", "fld dword ptr [rsp]\nfld dword ptr [rsp]\nfaddp\nfmulp\nfstp dword ptr [rsp]", None)
add("fsubp/fsubrp", "fld dword ptr [rsp]\nfld dword ptr [rsp]\nfsubp\nfstp dword ptr [rsp]\nfld dword ptr [rsp]\nfld dword ptr [rsp]\nfsubrp\nfstp dword ptr [rsp]", None)
add("fcom/fcomp", "fld dword ptr [rsp]\nfmul dword ptr [rsp]\nfcom\nfcomp\nfcompp", "fld dword ptr [esp]\nfcom\nfcomp")
add("fnstsw/ax", "fnstsw ax", "fnstsw ax")
add("fnstcw/fldcw", "fnstcw word ptr [rsp]\nfldcw word ptr [rsp]", "fnstcw word ptr [esp]\nfldcw word ptr [esp]")
add("fnclex/fwait", "fnclex\nfwait", "fnclex\nfwait")
add("fldz/fld1", "fldz\nfld1\nfstp dword ptr [rsp]\nfstp dword ptr [rsp]", "fldz\nfld1\nfstp dword ptr [esp]\nfstp dword ptr [esp]")
add("fld const", "fldpi\nfldl2e\nfldlg2", None)
add("fxch", "fld dword ptr [rsp]\nfld dword ptr [rsp]\nfxch st(1)\nffree st(0)\nffree st(1)", None)
add("fsqrt/fabs", "fld dword ptr [rsp]\nfsqrt\nfabs\nfstp dword ptr [rsp]", None)
add("fchs", "fld dword ptr [rsp]\nfchs\nfstp dword ptr [rsp]", None)
add("fprem", "fld1\nfld1\nfprem\nfstp dword ptr [rsp]\nfstp dword ptr [rsp]", None)
add("frndint", "fld dword ptr [rsp]\nfrndint\nfstp dword ptr [rsp]", None)
add("fucomi/fcomip", "fld dword ptr [rsp]\nfmul dword ptr [rsp]\nfucomi st(1)\nfcomip st(1)\nffree st(1)\nffree st(0)", None)
add("fucomp/fucom", "fld dword ptr [rsp]\nfld dword ptr [rsp]\nfucom\nfucomp\nfstp dword ptr [rsp]\nfstp dword ptr [rsp]", None)
add("fcmov", "fld dword ptr [rsp]\nfld dword ptr [rsp]\nfcmovb st, st(1)\nfcmovnu st, st(2)\nffree st(1)\nffree st(0)", None)
add("fyl2x", "fld1\nfldl2e\nfyl2x\nfstp dword ptr [rsp]", None)
add("fpatan", "fld1\nfld1\nfpatan\nfstp dword ptr [rsp]", None)
add("fistp dword", "fistp dword ptr [rsp]", "fistp dword ptr [esp]")
add("fdecstp/fincstp", "fldz\nfdecstp\nfincstp\nfldz\nfstp dword ptr [rsp]\nfstp dword ptr [rsp]", None)

# SSE float (single-precision base)
add("movss/movups", "movss xmm0, dword ptr [rsp]\nmovups [rsp], xmm0", None)
add("addss/subss/mulss", "movss xmm0, dword ptr [rsp]\nmovss xmm1, dword ptr [rsp]\naddss xmm0, xmm1\nsubss xmm0, xmm1\nmulss xmm0, xmm1\nmovss [rsp], xmm0", None)
add("divss", "movss xmm0, dword ptr [rsp]\nmovss xmm1, xmm0\nmovss xmm2, xmm0\naddss xmm2, xmm2\ndivss xmm2, xmm1\nmovss [rsp], xmm2", None)
add("addps/mulps/ps", "movaps [rsp], xmm1\nmovss [rsp], xmm2\nmovups xmm0, [rsp]\nmovss xmm2, xmm0\naddps xmm0, xmm2\nmulps xmm0, xmm2\nmovups [rsp], xmm0", None)
add("subps/divps/andps/orps/xorps", "xorps xmm0, xmm0\nmov rax, 0x1111111111111111\nmov [rsp], rax\nmovups xmm1, [rsp]\nmovaps xmm1, xmm1", None)
add("sqrtss", "mov rax, 0x40400000\nmov dword ptr [rsp], eax\nmovss xmm0, dword ptr [rsp]\nsqrtss xmm1, xmm0\nmovss [rsp], xmm1", None)
add("sqrtps", "mov dword ptr [rsp], 0x40400000\nmovups xmm0, [rsp]\nsqrtps xmm1, xmm0\nmovups [rsp], xmm1", None)
add("movdqa/movdqu", "movdqa xmm0, [rsp]\nmovdqu [rsp], xmm0", None)
add("movd/movq", "movd eax, xmm0\nmovd xmm0, eax\nmovq [rsp], xmm0\nmovq xmm1, [rsp]\nmovq xmm1, xmm0", None)
add("cvtss2sd etc", "mov dword ptr [rsp], 0x40400000\nmovss xmm0, dword ptr [rsp]\ncvtss2sd xmm1, xmm0\ncvttsd2si rax, xmm1\nmovaps [rsp], xmm1\nmovaps xmm2, [rsp]", None)
add("cvttsd2si/cvtsd2ss", "mov rax, 0x4000000000000000\nmov [rsp], rax\nmovsd xmm0, [rsp]\ncvttsd2si rcx, xmm0\ncvtsd2ss xmm1, xmm0\nmovss [rsp], xmm1", None)
add("cvtdq2ps etc", "movd xmm0, eax\ncvtdq2ps xmm1, xmm0\ncvtps2dq xmm2, xmm1", None)
add("unpck/shuf", "xorps xmm0, xmm0\nxorps xmm1, xmm1\nunpckhps xmm0, xmm1\nunpcklps xmm0, xmm1\nshufps xmm0, xmm1, 0xE4", None)
add("shufps", "xorps xmm0, xmm0\nshufps xmm0, xmm0, 0xE4", None)
add("movhlps/movlhps", "xorps xmm0, xmm0\nxorps xmm1, xmm1\nmovhlps xmm0, xmm1\nmovlhps xmm1, xmm0\nxorps xmm0, xmm0", None)
add("cmpeqps/cmpeqss", "xorps xmm0, xmm0\ncmpss xmm0, xmm0, 0", None)
add("andps/andnps/orps/xorps full", "mov rax, 0x1010101010101010\nmov [rsp], rax\nmovups xmm0, [rsp]\nmovaps xmm1, xmm0\nxorps xmm2, xmm2", None)
add("sse shift", "movd xmm0, eax\npslld xmm0, 2\ncvtdq2pd xmm1, xmm0", None)
add("pmul etc (mmx legacy)", "movd mm0, eax\npaddd mm0, mm1\nemms", None)
add("pinsrd/pextrd", "pinsrd xmm0, eax, 0\npextrd eax, xmm0, 0", None)
add("movlpd/movhpd", "movlpd xmm0, [rsp]\nmovhpd xmm1, [rsp+8]\nmovlpd [rsp], xmm0", None)
add("66 movs", "movaps xmm3, xmm0\nmovaps xmm4, xmm3", None)

# two-byte misc
extra_pro = {
}

def main(mode):
    exe = conftest.X64_DIR / "shellterpreter.exe" if mode == "x64" else conftest.X86_DIR / "shellterpreter.exe"
    results = {}
    for name, x64, x86 in T:
        asm = x64 if mode == "x64" else x86
        if asm is None:
            continue
        data = blob(asm, mode)
        if data is None:
            results[name] = "ASMERR"
            continue
        rc, err = run(exe, data)
        results[name] = classify(rc) + ("" if rc == EAX_OK else f"({rc:#x})")
    groups = {"OK": [], "UNSUP": [], "MEMSHARE": [], "OTHER": [], "ASMERR": []}
    for name, r in results.items():
        groups[r.split("(")[0]].append(f"{name}({r.split('(')[1][:-1] if '(' in r else ''})")
    for g in ("UNSUP", "MEMSHARE", "OTHER", "ASMERR", "OK"):
        if groups[g]:
            print(f"== {g} ({len(groups[g])}) ==")
            for n in groups[g]:
                print("  " + n)
    ok = len(groups["OK"])
    print(f"[{mode}] ok={ok} unsupported={len(groups['UNSUP'])} mem={len(groups['MEMSHARE'])} other={len(groups['OTHER'])} asmerr={len(groups['ASMERR'])}")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "all")
