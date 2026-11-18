"""Batch H task 5: real-binary smoke tests (audit #18).

Runs real Windows tool blobs (ipconfig / hostname / whoami) through the
interpreter. The blobs live in the directory named by SHELLTERP_BLOBS as
<name>.shellcode files; without the env var the tests skip (CI-safe).

Batch H task 6b: atexit-family registration (_onexit/__dllonexit) is an
emulated no-op, so the native doexit walk finds no guest callbacks and both
blobs exit deterministically 0 (previously a racy native teardown crash on
whoami). The exit assertions are hard.
"""

import os
import pathlib
import re
import subprocess

import pytest

import conftest

BLOBS = os.environ.get("SHELLTERP_BLOBS", "")


def run_blob(name, timeout=120):
    """Run <name>.shellcode from SHELLTERP_BLOBS; returns (exitcode, stdout)."""
    blob = pathlib.Path(BLOBS) / f"{name}.shellcode"
    exe = conftest.X64_DIR / "shellterpreter.exe"
    r = subprocess.run([str(exe), str(blob)], capture_output=True, text=True,
                       timeout=timeout)
    return conftest.win_code(r.returncode), (r.stdout or "").strip()


def _skip_unless_blob(name):
    if not BLOBS:
        pytest.skip("SHELLTERP_BLOBS not set")
    if not (pathlib.Path(BLOBS) / f"{name}.shellcode").exists():
        pytest.skip(f"{name}.shellcode not in SHELLTERP_BLOBS")


def test_ipconfig_exit0():
    _skip_unless_blob("ipconfig")
    code, _ = run_blob("ipconfig")
    assert code == 0, f"exit=0x{code:08X}"


def test_hostname_stdout():
    _skip_unless_blob("hostname")
    code, out = run_blob("hostname")
    assert out, "empty stdout"
    assert re.fullmatch(r"[A-Za-z0-9\-]+", out), f"stdout={out!r}"
    assert code == 0, f"exit=0x{code:08X}"


def test_whoami_stdout():
    _skip_unless_blob("whoami")
    code, out = run_blob("whoami")
    assert out, "empty stdout"
    assert re.match(r"^.+[\\\\/].+$", out), f"stdout={out!r}"
    assert code == 0, f"exit=0x{code:08X}"
