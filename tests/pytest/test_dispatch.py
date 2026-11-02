import conftest


def test_dual_arch_x64_exe_runs_x86_fault(tmp_path):
    exe = conftest.X64_DIR / "shellterpreter.exe"
    sc = tmp_path / "bad86.bin"
    sc.write_bytes(b"\x0f\xff")
    r = conftest.run([str(exe), str(sc), "--x86"])
    assert conftest.win_code(r.returncode) == 0xE0000001, (conftest.win_code(r.returncode), r.stderr[-2000:])
