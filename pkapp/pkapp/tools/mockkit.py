"""mockkit — mock runtime / 最小 PE / fake wheels 构造器（tools 与 tests 共用）。

Mock 先行（M0 决策）：真 PBS 快照接入后，同一管线/断言复验（G11 由 make_runtime_proto 承担）。
"""
from __future__ import annotations

import base64
import hashlib
import os
import struct
import zipfile


# ---------------------------------------------------------------- 最小 PE64 构造器
def build_pe(dll_names: list[str], machine: int = 0x8664) -> bytes:
    """构造仅含导入表（DLL 级）的可解析 PE 文件——闭包测试（B.s/G7）的真源。"""
    names = bytearray()
    name_rvas: list[int] = []
    for n in dll_names:
        name_rvas.append(0x1000 + len(names))
        names += n.encode("ascii") + b"\0"
    names += b"\0" * ((-len(names)) % 16)
    desc_rva = 0x1000 + len(names)
    descs = b"".join(struct.pack("<IIIII", 0, 0, 0, r, 0) for r in name_rvas) + b"\0" * 20
    section = bytes(names) + descs
    sec_size = (len(section) + 0x1FF) & ~0x1FF

    e_lfanew = 0x80
    hdr = bytearray(0x200)
    hdr[0:2] = b"MZ"
    struct.pack_into("<I", hdr, 0x3C, e_lfanew)
    coff = e_lfanew + 4                                 # COFF 紧跟 4 字节 PE 签名
    hdr[coff - 4:coff] = b"PE\x00\x00"
    struct.pack_into("<HHIIIHH", hdr, coff,
                     machine, 1, 0, 0, 0, 0xF0, 0x2022)
    opt = coff + 20                                     # OptionalHeader 起始（0x98）
    struct.pack_into("<HBBIIIIIQIIHHHHHHIIIIHHQQQQII", hdr, opt,
                     0x20B, 14, 0, 0x200, sec_size, 0, 0, 0x1000,
                     0x180000000, 0x1000, 0x200,
                     6, 0, 0, 0, 6, 0,
                     0, 0x2000, 0x200, 0, 3, 0,
                     0x100000, 0x1000, 0x100000, 0x1000, 0, 16)
    ddir = opt + 112                                    # PE32+ 数据目录（项 1 = Import）
    struct.pack_into("<II", hdr, ddir + 8, desc_rva, len(descs))
    sec = opt + 0xF0
    hdr[sec:sec + 8] = b".rdata\0\0"
    struct.pack_into("<IIIIIIHHI", hdr, sec + 8,
                     len(section), 0x1000, sec_size, 0x200, 0, 0, 0, 0, 0x40000040)
    return bytes(hdr) + section.ljust(sec_size, b"\0")


# ---------------------------------------------------------------- mock runtime
def make_mock_runtime(root: str) -> str:
    """构造与 §3.1 同构的假 PBS 安装目录（B.t① 共享构建形态；DLLs 含 B.s 最小闭包样例）。"""
    os.makedirs(os.path.join(root, "Lib", "json"), exist_ok=True)
    os.makedirs(os.path.join(root, "DLLs"), exist_ok=True)
    with open(os.path.join(root, "python312.dll"), "wb") as f:
        f.write(build_pe(["VCRUNTIME140.dll", "KERNEL32.dll",
                          "api-ms-win-crt-heap-l1-1-0.dll"]))
    with open(os.path.join(root, "python.exe"), "wb") as f:
        f.write(b"presence-only")                       # 解析器只断言在位
    with open(os.path.join(root, "Lib", "os.py"), "w") as f:
        f.write("a = 1\n")
    with open(os.path.join(root, "Lib", "json", "__init__.py"), "w") as f:
        f.write("b = 2\n")
    pe = build_pe
    with open(os.path.join(root, "DLLs", "_ssl.pyd"), "wb") as f:
        f.write(pe(["LIBCRYPTO-3-X64.dll", "LIBSSL-3-X64.dll", "VCRUNTIME140.dll"]))
    with open(os.path.join(root, "DLLs", "libcrypto-3-x64.dll"), "wb") as f:
        f.write(pe(["ADVAPI32.dll", "WS2_32.dll", "VCRUNTIME140.dll"]))
    with open(os.path.join(root, "DLLs", "libssl-3-x64.dll"), "wb") as f:
        f.write(pe(["LIBCRYPTO-3-X64.dll", "VCRUNTIME140.dll"]))
    with open(os.path.join(root, "DLLs", "_asyncio.pyd"), "wb") as f:
        f.write(pe(["VCRUNTIME140.dll", "KERNEL32.dll"]))
    return root


# ---------------------------------------------------------------- fake wheels
def make_mock_android_runtime(root: str, abis: tuple = ("arm64-v8a",)) -> str:
    """构造 flet python-build android 产物同构假快照：<root>/<abi>/{libpython3NN.so, 支持库, bundle}。

    libpythonbundle.so 是 zip（stdlib/ + modules/）——同构构造，供 spk runtime_hash 复算。
    """
    for abi in abis:
        d = os.path.join(root, abi)
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, "libpython3.12.so"), "wb") as f:
            f.write(b"\x7fELF-mock-libpython")
        with open(os.path.join(d, "libssl_python.so"), "wb") as f:
            f.write(b"\x7fELF-mock-ssl")
        with zipfile.ZipFile(os.path.join(d, "libpythonbundle.so"), "w") as zf:
            zf.writestr("stdlib/os.py", "a = 1\n")
            zf.writestr("modules/_mock_ext.so", b"\x7fELF-mock-module")
    return root


def make_wheel(wheels_dir: str, name: str, version: str,
               files: dict[str, str]) -> str:
    """构造最小合法 wheel（METADATA/WHEEL/RECORD 齐全），pip --no-index 可装入。"""
    dist = f"{name}-{version}.dist-info"
    members: list[tuple[str, bytes]] = [
        (f"{dist}/METADATA",
         f"Metadata-Version: 2.1\nName: {name}\nVersion: {version}\nSummary: test\n".encode()),
        (f"{dist}/WHEEL",
         b"Wheel-Version: 1.0\nGenerator: pkapp-test\nRoot-Is-Purelib: true\nTag: py3-none-any\n"),
        (f"{dist}/top_level.txt", name.encode()),
    ]
    for rel, text in files.items():
        members.append((rel, text.encode()))
    rec_lines = []
    for rel, data in members:
        digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()
        rec_lines.append(f"{rel},sha256={digest},{len(data)}")
    rec_lines.append(f"{dist}/RECORD,,")
    members.append((f"{dist}/RECORD", "\n".join(rec_lines).encode()))

    path = os.path.join(wheels_dir, f"{name}-{version}-py3-none-any.whl")
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
        for rel, data in members:
            zf.writestr(rel, data)
    return path
