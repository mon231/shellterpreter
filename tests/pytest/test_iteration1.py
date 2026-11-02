import conftest


def test_calc_x64():
    exe = conftest.X64_DIR / "shellterpreter.exe"
    sc = conftest.X64_DIR / "01_simple_calc.shellcode"
    r = conftest.run([str(exe), str(sc)])
    assert r.returncode == 4950, (conftest.win_code(r.returncode), r.stderr[-2000:])


def test_unknown_opcode_x64(tmp_path):
    exe = conftest.X64_DIR / "shellterpreter.exe"
    sc = tmp_path / "bad.bin"
    sc.write_bytes(b"\x0f\xff")
    r = conftest.run([str(exe), str(sc), "--x64"])
    assert conftest.win_code(r.returncode) == 0xE0000001, r.stderr[-2000:]
