import conftest

# exception support (iteration 6): C++ try/catch (07, 11, 15) and SEH (12).
# Each test PE returns its project number once the exception was caught.


def _run(exe_dir, name):
    exe = exe_dir / "shellterpreter.exe"
    sc = exe_dir / f"{name}.shellcode"
    assert sc.exists(), f"{name}.shellcode was not built"
    return conftest.run([str(exe), str(sc)])


def test_cpp_exception_x64():
    r = _run(conftest.X64_DIR, "07_cpp_exceptions")
    assert r.returncode == 7, (conftest.win_code(r.returncode), r.stderr[-2000:])


def test_cpp_exception_x86():
    r = _run(conftest.X86_DIR, "07_cpp_exceptions")
    assert r.returncode == 7, (conftest.win_code(r.returncode), r.stderr[-2000:])


def test_cpp_exception_frames_x64():
    r = _run(conftest.X64_DIR, "11_cpp_exceptions")
    assert r.returncode == 11, (conftest.win_code(r.returncode), r.stderr[-2000:])


def test_cpp_exception_frames_x86():
    r = _run(conftest.X86_DIR, "11_cpp_exceptions")
    assert r.returncode == 11, (conftest.win_code(r.returncode), r.stderr[-2000:])


def test_seh_exception_x64():
    r = _run(conftest.X64_DIR, "12_seh_exceptions")
    assert r.returncode == 12, (conftest.win_code(r.returncode), r.stderr[-2000:])


def test_seh_exception_x86():
    r = _run(conftest.X86_DIR, "12_seh_exceptions")
    assert r.returncode == 12, (conftest.win_code(r.returncode), r.stderr[-2000:])


def test_nested_exception_x64():
    r = _run(conftest.X64_DIR, "15_nested_exceptions")
    assert r.returncode == 15, (conftest.win_code(r.returncode), r.stderr[-2000:])


def test_nested_exception_x86():
    r = _run(conftest.X86_DIR, "15_nested_exceptions")
    assert r.returncode == 15, (conftest.win_code(r.returncode), r.stderr[-2000:])
