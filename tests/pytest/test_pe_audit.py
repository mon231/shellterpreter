import sys
import pathlib
import pytest
import conftest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2] / "scripts"))
import audit_pe


@pytest.mark.parametrize("path", [
    conftest.X64_DIR / "shellterpreter.exe",
    conftest.X64_DIR / "01_simple_calc.exe",
])
def test_no_rwx_no_extra_exec(path):
    execs, rwx = audit_pe.audit(path)
    assert rwx == []
    assert set(execs) == {".text"}
