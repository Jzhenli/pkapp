"""PE 导入表读取器往返测试（B.s 基础设施）。"""
import pytest

from pkapp.packager.pe import PEError, read_imports
from pkapp.tools.mockkit import build_pe


def test_roundtrip():
    names = ["LIBCRYPTO-3-X64.dll", "LIBSSL-3-X64.dll", "VCRUNTIME140.dll"]
    assert sorted(set(read_imports(build_pe(names)))) == sorted(set(names))


def test_no_import_dir():
    # 无导入目录（数据目录全零）→ 空表，不抛
    data = bytearray(build_pe([]))
    assert read_imports(bytes(data)) == []


def test_garbage_raises():
    with pytest.raises(PEError):
        read_imports(b"not a pe file at all")
    with pytest.raises(PEError):
        read_imports(b"MZ" + b"\0" * 64)
