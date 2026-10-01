"""PE 导入表读取器（协议 B B.s：Windows 原生依赖闭包）。

纯 stdlib struct 实现，只读导入目录（无需 pefile）。作用：
对 DLLs/ 下每个 .pyd / .dll 解析其 import DLL 名单 → packager 计算传递闭包，
闭包不完整 → 构建失败（B.s：不得留给真机 ImportError；G7 负向用例即此路径）。
"""
from __future__ import annotations

import struct

_MACHINE_NAMES = {0x8664: "x64", 0x14C: "x86", 0xAA64: "arm64"}


class PEError(ValueError):
    """非 PE / 结构损坏。"""


def _rva_to_offset(rva: int, sections: list[tuple[int, int, int]]) -> int:
    for va, vsize, raw in sections:
        if va <= rva < va + vsize:
            return raw + (rva - va)
    raise PEError(f"RVA {rva:#x} 不在任何 section 内")


def read_imports(data: bytes) -> list[str]:
    """解析 PE32+/PE32 导入表，返回被导入的 DLL 名列表（保留原始大小写、可含重复）。"""
    if len(data) < 0x40 or data[:2] != b"MZ":
        raise PEError("不是 PE 文件（缺 MZ）")
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if data[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
        raise PEError("不是 PE 文件（缺 PE 签名）")
    coff = e_lfanew + 4
    machine, nsec, _, _, _, opt_size, _ = struct.unpack_from("<HHIIIHH", data, coff)
    opt = coff + 20
    magic = struct.unpack_from("<H", data, opt)[0]
    if magic == 0x20B:            # PE32+
        ddir_off = opt + 112
    elif magic == 0x10B:          # PE32
        ddir_off = opt + 96
    else:
        raise PEError(f"未知 OptionalHeader magic: {magic:#x}")
    imp_rva, imp_size = struct.unpack_from("<II", data, ddir_off + 8)  # 目录项 1 = Import
    if opt_size < (ddir_off - opt) + 8:
        raise PEError("OptionalHeader 过短，无数据目录")
    sec_off = opt + opt_size
    sections = []
    for i in range(nsec):
        o = sec_off + i * 40
        vsize, va, rsize, roff = struct.unpack_from("<IIII", data, o + 8)
        sections.append((va, vsize, roff))

    out: list[str] = []
    if not imp_rva:
        return out
    off = _rva_to_offset(imp_rva, sections)
    while True:
        if off + 20 > len(data):
            raise PEError("导入描述符表越界")
        ilt, _, _, name_rva, iat = struct.unpack_from("<IIIII", data, off)
        if ilt == 0 and name_rva == 0 and iat == 0:
            break
        if name_rva:
            noff = _rva_to_offset(name_rva, sections)
            end = data.index(b"\x00", noff)
            out.append(data[noff:end].decode("ascii", "replace"))
        # 闭包只按 DLL 级（B.s）：描述符 name_rva 即足够，无需遍历 ILT 函数项
        off += 20
    return out
