import conftest


def test_builds_x64():
    r = conftest.build("x64")
    assert r.returncode == 0, r.stdout[-4000:]
    assert (conftest.X64_DIR / "shellterpreter.exe").exists()
    assert (conftest.X64_DIR / "01_simple_calc.exe").exists()
    assert (conftest.X64_DIR / "01_simple_calc.shellcode").exists()
