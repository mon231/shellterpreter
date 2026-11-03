import pytest

import conftest

# jmp $: an endless spin; the ONLY way it stops is the budget fault,
# so the pin is exact and cannot pass by half-working emulation.
# Raw (non-PE) bytes default to no architecture: the arch flag is required.

_ARCH = {conftest.X64_DIR: ["--x64"], conftest.X86_DIR: ["--x86"]}


@pytest.mark.parametrize("exe_dir", [conftest.X64_DIR, conftest.X86_DIR])
def test_budget_fault(monkeypatch, tmp_path, exe_dir):
    monkeypatch.setenv("SHELLTERP_BUDGET", "128")
    exe = exe_dir / "shellterpreter.exe"
    sc = tmp_path / "spin.bin"
    sc.write_bytes(b"\xeb\xfe")
    r = conftest.run([str(exe), str(sc)] + _ARCH[exe_dir])
    assert conftest.win_code(r.returncode) == 0xE0000009, (
        conftest.win_code(r.returncode), r.stderr[-2000:])


@pytest.mark.parametrize("exe_dir", [conftest.X64_DIR, conftest.X86_DIR])
def test_budget_min(monkeypatch, tmp_path, exe_dir):
    monkeypatch.setenv("SHELLTERP_BUDGET", "1")
    exe = exe_dir / "shellterpreter.exe"
    sc = tmp_path / "spin.bin"
    sc.write_bytes(b"\xeb\xfe")
    r = conftest.run([str(exe), str(sc)] + _ARCH[exe_dir])
    assert conftest.win_code(r.returncode) == 0xE0000009, (
        conftest.win_code(r.returncode), r.stderr[-2000:])
