"""发布制品链测试：壳公钥补丁 / 内置壳 fallback / 自动 keygen / wheel 播种（★方案 A★）。

覆盖零配置主线的关键接缝：
- 分发壳（仓库默认 / 包内置）package 时公钥原位补丁 → 任意项目密钥 × 零编译壳
- build 私钥缺失自动 keygen → create 后无需任何签名前置知识
- 内置 wheel 播种托管缓存 → applocal（非 PyPI 私有件）的离线唯一入口
"""
from __future__ import annotations

import os

import pytest

from pkapp.commands.package import (
    _SHELL_DEFAULT_PUB,
    _find_shell,
    _patch_shell_pubkey,
)
from pkapp.packager import sign


def _fake_exe(default_pub: bool, extra_runs: int = 0) -> bytes:
    """构造带公钥常量的假 exe 字节：默认公钥命中 or 自定义 64-hex 段 + 干扰段。"""
    body = b"\x00MZ-stub\x00"
    if default_pub:
        body += _SHELL_DEFAULT_PUB.encode("ascii")
    else:
        body += b"ab" * 31 + b"cd"  # 64 字符 hex 自定义公钥段
    for i in range(extra_runs):
        body += b"\x01" + b"ef" * 32 + b"\x02"
    return body + b"\xff\xee-tail"


def test_patch_pubkey_default_hit(tmp_path):
    exe = tmp_path / "MyApp.exe"
    original = _fake_exe(default_pub=True)
    exe.write_bytes(original)
    new_pub = sign.generate_keypair(str(tmp_path / "kd"))[1]
    _patch_shell_pubkey(str(exe), new_pub)
    patched = exe.read_bytes()
    assert len(patched) == len(original)
    assert new_pub.lower().encode("ascii") in patched
    assert _SHELL_DEFAULT_PUB.encode("ascii") not in patched


def test_patch_pubkey_unique_run_fallback(tmp_path):
    """自定义 pub 编译的壳（无默认锚点）：唯一 64-hex 段命中改写。"""
    exe = tmp_path / "MyApp.exe"
    original = _fake_exe(default_pub=False)
    exe.write_bytes(original)
    new_pub = sign.generate_keypair(str(tmp_path / "kd"))[1]
    _patch_shell_pubkey(str(exe), new_pub)
    assert new_pub.lower().encode("ascii") in exe.read_bytes()


def test_patch_pubkey_ambiguous_rejected(tmp_path):
    """多段 64-hex：定位不可靠，必须报错走模式 B（绝不盲改）。"""
    exe = tmp_path / "MyApp.exe"
    exe.write_bytes(_fake_exe(default_pub=False, extra_runs=2))
    with pytest.raises(RuntimeError, match="64-hex"):
        _patch_shell_pubkey(str(exe), sign.generate_keypair(str(tmp_path / "kd"))[1])


def test_patch_pubkey_rejects_bad_pub(tmp_path):
    exe = tmp_path / "MyApp.exe"
    exe.write_bytes(_fake_exe(default_pub=True))
    with pytest.raises(RuntimeError, match="64 位 hex"):
        _patch_shell_pubkey(str(exe), "zz")


def test_find_shell_explicit_not_patchable(tmp_path):
    exe = tmp_path / "shell.exe"
    exe.write_bytes(b"x")
    path, patchable = _find_shell(str(exe))
    assert path == str(exe) and patchable is False   # 用户自管壳（模式 B）不补丁


def test_find_shell_vendored_fallback(monkeypatch, tmp_path):
    """仓库默认壳缺席时回落包内置壳（可补丁）。"""
    from pkapp import vendor
    from pkapp.commands import package as pkg

    exe = tmp_path / "MyApp.exe"
    exe.write_bytes(b"x")
    monkeypatch.setattr(vendor, "shell_exe", lambda: str(exe))
    real_isfile = os.path.isfile
    repo = os.path.dirname(os.path.dirname(os.path.dirname(
        os.path.dirname(os.path.abspath(pkg.__file__)))))
    repo_default = os.path.join(repo, "shell-windows", "build", "MyApp.exe")

    def fake_isfile(p):
        return False if str(p) == repo_default else real_isfile(p)

    monkeypatch.setattr(pkg.os.path, "isfile", fake_isfile)
    path, patchable = _find_shell(None)
    assert path == str(exe) and patchable is True


def test_build_auto_keygen(tmp_path, mock_runtime, wheels_dir):
    """create 后零签名知识直接 build：私钥自动生成到 .pkapp/sign.key。"""
    from pkapp.commands.build import cmd_build
    from pkapp.commands.create import cmd_create

    root = str(tmp_path / "nokey")
    assert cmd_create("nokey", root, no_venv=True) == 0
    assert not os.path.isfile(os.path.join(root, ".pkapp", "sign.key"))
    assert cmd_build(root, platform="windows", wheels_dir=wheels_dir) == 0
    assert os.path.isfile(os.path.join(root, ".pkapp", "sign.key"))


def test_seed_vendored_wheel(tmp_path, pkapp_cache, monkeypatch):
    """内置 wheel 播种托管缓存：首次拷入、重复幂等（已有同名包不覆盖）。"""
    from pkapp import vendor
    from pkapp.commands.build import _seed_vendored_wheel
    from pkapp.packager.assemble import _wheels_cache
    from pkapp.tools.mockkit import make_wheel

    src = tmp_path / "vw"
    src.mkdir()
    make_wheel(str(src), "applocal", "0.1.0", {"applocal/__init__.py": ""})
    monkeypatch.setattr(vendor, "wheels_dir", lambda: str(src))

    _seed_vendored_wheel("windows")
    cache = _wheels_cache("windows")
    seeded = [f for f in os.listdir(cache) if f.startswith("applocal-")]
    assert len(seeded) == 1

    make_wheel(str(src), "applocal", "0.2.0", {"applocal/__init__.py": ""})
    _seed_vendored_wheel("windows")   # 缓存已有 applocal → 不覆盖
    assert len([f for f in os.listdir(cache) if f.startswith("applocal-")]) == 1


def test_seed_vendored_wheel_absent_quiet(pkapp_cache):
    """源码/测试形态无 _vendor：播种为静默 no-op（零配置主线的优雅降级）。"""
    from pkapp.commands.build import _seed_vendored_wheel
    assert _seed_vendored_wheel("windows") is None
