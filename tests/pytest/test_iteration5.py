import conftest


def _run(exe_dir, name, extra=()):
    exe = exe_dir / "shellterpreter.exe"
    sc = exe_dir / f"{name}.shellcode"
    assert sc.exists(), f"{name}.shellcode was not built"
    return conftest.run([str(exe), str(sc), *extra])


def _check_thread(exe_dir):
    # std::thread: the joined thread writes 42 into the main thread's local
    r = _run(exe_dir, "08_cpp_thread")
    assert r.returncode == 42, (conftest.win_code(r.returncode), r.stderr[-2000:])


def test_thread_x64():
    _check_thread(conftest.X64_DIR)


def test_thread_x86():
    _check_thread(conftest.X86_DIR)


def test_thread_dual_arch():
    # x64 interpreter runs x86 thread shellcode
    sc = conftest.X86_DIR / "08_cpp_thread.shellcode"
    assert sc.exists(), "08_cpp_thread.shellcode was not built"
    r = conftest.run([str(conftest.X64_DIR / "shellterpreter.exe"), str(sc)])
    assert r.returncode == 42, (conftest.win_code(r.returncode), r.stderr[-2000:])
