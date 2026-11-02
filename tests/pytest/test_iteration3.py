import conftest


def _run_relocs(exe_dir, extra=()):
    exe = exe_dir / "shellterpreter.exe"
    sc = exe_dir / "02_relocs.shellcode"
    r = conftest.run([str(exe), str(sc), *extra])
    assert sc.exists(), "02_relocs.shellcode was not built"
    return r


def test_relocs_x64():
    r = _run_relocs(conftest.X64_DIR)
    assert r.returncode == 542, (conftest.win_code(r.returncode), r.stderr[-2000:])


def test_relocs_x86():
    r = _run_relocs(conftest.X86_DIR)
    assert r.returncode == 542, (conftest.win_code(r.returncode), r.stderr[-2000:])


def test_relocs_dual_arch():
    r = _run_relocs(conftest.X86_DIR, ["--x86"])
    assert r.returncode == 542, (conftest.win_code(r.returncode), r.stderr[-2000:])
