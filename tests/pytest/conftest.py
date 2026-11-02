import os
import pathlib
import subprocess

ROOT = pathlib.Path(__file__).resolve().parents[2]

# SHELLTERP_CONFIG=Debug runs the test suite against Debug_x64/Debug_Win32 exes.
CONFIG = os.environ.get("SHELLTERP_CONFIG", "Release")
X64_DIR = ROOT / ("Debug_x64" if CONFIG == "Debug" else "Win_x64")
X86_DIR = ROOT / ("Debug_Win32" if CONFIG == "Debug" else "Win_x86")


def win_code(rc: int) -> int:
    if rc < 0:
        return rc + (1 << 32)
    return rc


def run(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, **kw)


def msbuild_path():
    vsw = pathlib.Path(os_environ_vswhere())
    if not vsw.exists():
        return None
    out = subprocess.run([str(vsw), "-latest", "-products", "*",
                          "-requires", "Microsoft.VisualStudio.Component.VC.Tools.x86.x64",
                          "-property", "installationPath"],
                         capture_output=True, text=True)
    p = out.stdout.strip()
    if not p:
        return None
    return pathlib.Path(p) / "MSBuild" / "Current" / "Bin" / "MSBuild.exe"


def os_environ_vswhere():
    import os
    return os.path.join(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)"),
                        "Microsoft Visual Studio", "Installer", "vswhere.exe")


def build(platform: str, configuration: str = "Release"):
    msbuild = msbuild_path()
    if msbuild is None:
        raise RuntimeError("msbuild not found")
    return run([str(msbuild), str(ROOT / "shellterpreter.sln"),
                f"/p:Configuration={configuration}", f"/p:Platform={platform}",
                "/m", "/v:m", "/nologo"])
