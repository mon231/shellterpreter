"""Iteration 7: fuzz-ish hardening tests.

Malformed and mutated shellcode must always end in a clean interpreter exit:
either a normal guest result (exit code < 0xE0000000) or one of the reserved
fault codes 0xE0000001..0xE0000009. A native crash (0xC0000005 and friends)
or a hang is a bug: the interpreter must fail closed, never crash.
"""

import os
import pathlib
import random
import subprocess

import conftest

FAULT_LO = 0xE0000001
FAULT_HI = 0xE0000009
TMP = pathlib.Path(r"C:\Users\avart\AppData\Local\Temp\opencode\fuzz")
# mutated code can wander through long paths; the budget keeps Debug builds
# (slow per instruction) inside the timeout instead of tripping it
ENV = dict(os.environ, SHELLTERP_BUDGET="50000000")


def _clean_exit(returncode: int) -> bool:
    c = conftest.win_code(returncode)
    return c < 0xE0000000 or FAULT_LO <= c <= FAULT_HI


def _run_checked(exe, sc_path):
    try:
        r = subprocess.run([str(exe), str(sc_path)], capture_output=True,
                           timeout=30, env=ENV)
    except subprocess.TimeoutExpired:
        return False, "hang"
    if not _clean_exit(r.returncode):
        return False, "exit=0x%X" % conftest.win_code(r.returncode)
    return True, ""


def test_malformed_files_x64():
    exe = conftest.X64_DIR / "shellterpreter.exe"
    TMP.mkdir(parents=True, exist_ok=True)
    rng = random.Random(7)
    cases = {
        "empty.bin": b"",
        "mz_garbage.bin": b"MZ" + bytes(rng.randrange(256) for _ in range(64)),
        "rand.bin": bytes(rng.randrange(256) for _ in range(256)),
        # MZ header claiming a PE at 0x40, then a truncated PE signature
        "mz_pe_trunc.bin": b"MZ" + b"\0" * 14 + b"\x40\x00\x01\x00" + b"PE\0\0" + bytes(20),
    }
    for name, data in cases.items():
        p = TMP / name
        p.write_bytes(data)
        ok, why = _run_checked(exe, p)
        assert ok, f"{name}: {why}"


def test_truncated_shellcode_x64():
    exe = conftest.X64_DIR / "shellterpreter.exe"
    src = conftest.X64_DIR / "01_simple_calc.shellcode"
    assert src.exists(), "01_simple_calc.shellcode was not built"
    TMP.mkdir(parents=True, exist_ok=True)
    data = src.read_bytes()
    for cut in (1, 4, 16, 64):
        p = TMP / f"trunc{cut}.bin"
        p.write_bytes(data[:-cut])
        ok, why = _run_checked(exe, p)
        assert ok, f"cut {cut}: {why}"


def _mutation_fuzz(exe_dir, name, iterations, nmut, seed):
    exe = exe_dir / "shellterpreter.exe"
    src = exe_dir / f"{name}.shellcode"
    assert src.exists(), f"{name}.shellcode was not built"
    TMP.mkdir(parents=True, exist_ok=True)
    rng = random.Random(seed)
    data = src.read_bytes()
    for i in range(iterations):
        b = bytearray(data)
        for _ in range(nmut):
            b[rng.randrange(len(b))] = rng.randrange(256)
        p = TMP / f"mut_{name}_{i}.bin"
        p.write_bytes(b)
        ok, why = _run_checked(exe, p)
        assert ok, f"{name} mutation {i}: {why}"


def test_mutated_calc_x64():
    _mutation_fuzz(conftest.X64_DIR, "01_simple_calc", 20, 4, 42)


def test_mutated_calc_x86():
    _mutation_fuzz(conftest.X86_DIR, "01_simple_calc", 20, 4, 42)


def test_mutated_exceptions_x64():
    # the exception paths are the newest code: mutate through them too
    _mutation_fuzz(conftest.X64_DIR, "07_cpp_exceptions", 20, 8, 1234)


def test_mutated_exceptions_x86():
    _mutation_fuzz(conftest.X86_DIR, "07_cpp_exceptions", 20, 8, 1234)
