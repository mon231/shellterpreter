import conftest


def _run(exe_dir, extra=()):
    exe = exe_dir / "shellterpreter.exe"
    sc = exe_dir / "03_winapi_messagebox.shellcode"
    assert sc.exists(), "03_winapi_messagebox.shellcode was not built"
    return conftest.run([str(exe), str(sc), *extra])


def test_winapi_x64():
    r = _run(conftest.X64_DIR)
    assert r.returncode == 102, (conftest.win_code(r.returncode), r.stderr[-2000:])


def test_winapi_x86():
    r = _run(conftest.X86_DIR)
    assert r.returncode == 102, (conftest.win_code(r.returncode), r.stderr[-2000:])
