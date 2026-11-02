import conftest


def _run(exe_dir, name, extra=()):
    exe = exe_dir / "shellterpreter.exe"
    sc = exe_dir / f"{name}.shellcode"
    assert sc.exists(), f"{name}.shellcode was not built"
    return conftest.run([str(exe), str(sc), *extra])


def _msvcrt_rands(seed, n):
    s = seed
    vals = []
    for _ in range(n):
        s = (s * 214013 + 2531011) & 0xFFFFFFFF
        vals.append((s >> 16) & 0x7FFF)
    return vals


def test_winapi_x64():
    r = _run(conftest.X64_DIR, "03_winapi_messagebox")
    assert r.returncode == 102, (conftest.win_code(r.returncode), r.stderr[-2000:])


def test_winapi_x86():
    r = _run(conftest.X86_DIR, "03_winapi_messagebox")
    assert r.returncode == 102, (conftest.win_code(r.returncode), r.stderr[-2000:])


CRT_OUT = "crt-lo|42 -7 12345|4000000000 beef|ok Z|%"


def _check_crt(exe_dir):
    r = _run(exe_dir, "04_crt_printf_rand")
    expected = 100 + (sum(_msvcrt_rands(1234, 5)) % 1000)
    assert r.returncode == expected, (conftest.win_code(r.returncode), r.stderr[-2000:])
    assert r.stdout == CRT_OUT, repr(r.stdout)


def test_crt_x64():
    _check_crt(conftest.X64_DIR)


def test_crt_x86():
    _check_crt(conftest.X86_DIR)


def test_resources_x64():
    r = _run(conftest.X64_DIR, "09_resources")
    assert r.returncode == 600, (conftest.win_code(r.returncode), r.stderr[-2000:])


def test_resources_x86():
    r = _run(conftest.X86_DIR, "09_resources")
    assert r.returncode == 600, (conftest.win_code(r.returncode), r.stderr[-2000:])


def test_arch_dispatch():
    # x64 interpreter runs x86 shellcode
    sc = conftest.X86_DIR / "03_winapi_messagebox.shellcode"
    assert sc.exists(), "03_winapi_messagebox.shellcode was not built"
    r = conftest.run([str(conftest.X64_DIR / "shellterpreter.exe"), str(sc)])
    assert r.returncode == 102, (conftest.win_code(r.returncode), r.stderr[-2000:])

    # x86 interpreter refuses x64 shellcode
    sc64 = conftest.X64_DIR / "03_winapi_messagebox.shellcode"
    assert sc64.exists(), "03_winapi_messagebox.shellcode was not built"
    r = conftest.run([str(conftest.X86_DIR / "shellterpreter.exe"), str(sc64)])
    assert conftest.win_code(r.returncode) == 0xE0000007, (conftest.win_code(r.returncode), r.stderr[-2000:])
