import sys
import struct

EXEC = 0x20000000
WRITE = 0x80000000

ALLOWED_EXEC_DEFAULT = {".text"}


def sections(path):
    data = open(path, "rb").read()
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    assert data[e_lfanew:e_lfanew + 4] == b"PE\x00\x00"
    num_sec = struct.unpack_from("<H", data, e_lfanew + 6)[0]
    opt_size = struct.unpack_from("<H", data, e_lfanew + 20)[0]
    off = e_lfanew + 24 + opt_size
    out = []
    for i in range(num_sec):
        hdr = data[off + i * 40: off + i * 40 + 40]
        name = hdr[:8].rstrip(b"\x00").decode(errors="replace")
        vsize, vaddr = struct.unpack_from("<II", hdr, 8)
        chars = struct.unpack_from("<I", hdr, 36)[0]
        out.append((name, vsize, vaddr, chars))
    return out


def audit(path, allowed=None):
    allowed = allowed if allowed is not None else set(ALLOWED_EXEC_DEFAULT)
    execs, rwx = [], []
    for name, vsize, vaddr, chars in sections(path):
        if vsize and (chars & EXEC):
            execs.append(name)
            if chars & WRITE:
                rwx.append(name)
    return execs, rwx


if __name__ == "__main__":
    allowed = set(sys.argv[2:])
    execs, rwx = audit(sys.argv[1], allowed)
    print(f"exec sections: {execs}")
    if rwx:
        print(f"FAIL RWX sections: {rwx}")
        sys.exit(2)
    bad = [n for n in execs if n not in allowed]
    if bad:
        print(f"FAIL unexpected exec section(s): {bad}")
        sys.exit(3)
    print("OK")
