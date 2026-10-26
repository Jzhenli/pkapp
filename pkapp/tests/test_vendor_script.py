"""scripts/vendor.py 收录矩阵 / --require 闸门 / android 预编译移除回归（★H4 fail-fast 2026-10★）。

vendor.py 是仓库脚本（不在包内）——importlib 按路径加载，run(root=…) 注入假仓库树，
applocal wheel 构建步骤 monkeypatch 掉（pip wheel 不在被测面）。

被锁住的行为：
- 收录矩阵逐条目 OK/SKIP+原因输出（消灭静默跳过）；
- 硬闸门条目（shell-windows/keylib-windows/applocal-wheel）缺件直接非零退出；
- --require 命中 SKIP 条目 → rc=2 并列缺口；未知条目 → rc=2；
- android keylib 预编译件永不收录（单槽 so ABI 错配风险已移除）；
- linux keylib 预制件按 arch 收录 + 锚点字节校验（★linux 预制件 2026-10★，
  H4 的 arch 语义由 per-arch 分目录消解——与 android 单槽排除形成对照）；
- locate_dll("android") 仅认 PKAPP_KEYLIB env（keybuild 侧无退化路径配套）。
"""
from __future__ import annotations

import importlib.util
import os
import shutil

import pytest

from pkapp.packager.keylib import ANCHOR_HEX

_HERE = os.path.dirname(os.path.abspath(__file__))
_VENDOR_SCRIPT = os.path.join(os.path.dirname(_HERE), "scripts", "vendor.py")
_ANCHOR_BYTES = bytes.fromhex(ANCHOR_HEX)


@pytest.fixture
def vendor_mod():
    spec = importlib.util.spec_from_file_location("pkapp_vendor_script",
                                                  _VENDOR_SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture
def fake_repo(tmp_path):
    """假仓库树：十一条目收录原料齐备。keylib/build 额外放 lib_pkapp_key.so
    （android 预编译件——收录时必须被无视，回归锚）。"""
    root = tmp_path / "repo"
    sw = root / "shell-windows" / "build"
    sw.mkdir(parents=True)
    (sw / "MyApp.exe").write_bytes(b"MZ-fake-shell")
    (sw / "WebView2Loader.dll").write_bytes(b"fake-loader-dll")
    kb = root / "keylib" / "build"
    kb.mkdir(parents=True)
    (kb / "pkapp_key.dll").write_bytes(b"fake-key-holder-dll")
    (kb / "lib_pkapp_key.so").write_bytes(b"android-single-slot-so")
    for arch in ("x86_64", "aarch64", "armv7l"):      # linux keylib 通用件 ×3
        kbl = kb / "linux" / arch
        kbl.mkdir(parents=True)
        (kbl / "pkapp_key.so").write_bytes(
            b"\x7fELF-fake-so-" + arch.encode() + b"|" + _ANCHOR_BYTES + b"|")
    ks = root / "keylib" / "src"
    ks.mkdir(parents=True)
    (ks / "key.c").write_text("/* fake key.c */", encoding="utf-8")
    (ks / "key.h").write_text("/* fake key.h */", encoding="utf-8")
    sa = root / "shell-android" / "shell" / "app" / "src" / "main"
    sa.mkdir(parents=True)
    (sa / "AndroidManifest.xml").write_text("<manifest/>", encoding="utf-8")
    (root / "applocal").mkdir()
    sl = root / "shell-linux" / "build"                   # launcher ELF ×3（arch 分位）
    (sl / "aarch64").mkdir(parents=True)
    (sl / "armv7l").mkdir()
    (sl / "myapp").write_bytes(b"\x7fELF-fake-launcher-x64")
    (sl / "aarch64" / "myapp").write_bytes(b"\x7fELF-fake-launcher-a64")
    (sl / "armv7l" / "myapp").write_bytes(b"\x7fELF-fake-launcher-armv7")
    return str(root)


@pytest.fixture
def fake_wheel(monkeypatch):
    """pip wheel 步骤替换：vroot/wheels 落一个假 wheel（保持矩阵 OK 语义）。"""
    def _install(mod):
        def _fake_build(vroot, root):
            wd = os.path.join(vroot, "wheels")
            os.makedirs(wd, exist_ok=True)
            with open(os.path.join(wd, "applocal-0.0.0-py3-none-any.whl"), "wb") as f:
                f.write(b"fake-wheel")
            return "OK", "_vendor/wheels（1 wheel）"

        monkeypatch.setattr(mod, "_build_applocal_wheel", _fake_build)
    return _install


_REQUIRE_FULL = ("shell-windows,shell-linux-x86_64,shell-linux-aarch64,"
                 "shell-linux-armv7l,keylib-windows,keylib-linux-x86_64,"
                 "keylib-linux-aarch64,keylib-linux-armv7l,keylib-src,"
                 "shell-android,applocal-wheel")


def test_full_matrix_ok(vendor_mod, fake_repo, fake_wheel, capsys):
    """十一条目全齐 → rc=0，矩阵逐行 OK，产物落位正确（launcher/keylib ×3 arch 分目录）。"""
    fake_wheel(vendor_mod)
    rc = vendor_mod.run(["--require", _REQUIRE_FULL], root=fake_repo)
    assert rc == 0
    out = capsys.readouterr().out
    assert out.count("[vendor] OK:") == 11
    vroot = os.path.join(fake_repo, "pkapp", "pkapp", "_vendor")
    assert os.path.isfile(os.path.join(vroot, "shell", "MyApp.exe"))
    for arch in ("x86_64", "aarch64", "armv7l"):
        assert os.path.isfile(os.path.join(vroot, "shell-linux", arch, "myapp"))
        assert os.path.isfile(os.path.join(vroot, "keylib", "linux", arch,
                                           "pkapp_key.so"))
    assert os.path.isfile(os.path.join(vroot, "keylib", "windows", "pkapp_key.dll"))
    assert os.path.isfile(os.path.join(vroot, "keylib", "src", "key.c"))
    assert os.path.isfile(os.path.join(vroot, "shell-android", "app",
                                       "src", "main", "AndroidManifest.xml"))
    assert os.path.isfile(os.path.join(vroot, "wheels",
                                       "applocal-0.0.0-py3-none-any.whl"))


def test_android_prebuilt_never_vendored(vendor_mod, fake_repo, fake_wheel):
    """★H4 回归锚★：keylib/build/lib_pkapp_key.so 存在也不收录——
    _vendor/keylib/android 必须不存在（单槽 so 无 ABI 语义，锚点补丁会把
    错 ABI 件打进 APK）。linux per-arch 预制件是对照面（arch 显式分目录）。"""
    fake_wheel(vendor_mod)
    assert vendor_mod.run([], root=fake_repo) == 0
    vroot = os.path.join(fake_repo, "pkapp", "pkapp", "_vendor", "keylib")
    assert not os.path.isdir(os.path.join(vroot, "android"))
    assert sorted(os.listdir(vroot)) == ["linux", "src", "windows"]


def test_shell_linux_missing_is_skip_not_hard(vendor_mod, fake_wheel, tmp_path,
                                              capsys):
    """★M3 条 5★：launcher 缺件 → SKIP（可选条目，--require 命中才失败），
    且 SKIP 即清旧 _vendor/shell-linux（滞留件照常进 wheel=静默陈旧变体，H4 同款）。"""
    fake_wheel(vendor_mod)
    root = str(tmp_path / "repo-no-launcher")
    sw = os.path.join(root, "shell-windows", "build")     # 硬闸门原料齐（仅 launcher 缺）
    os.makedirs(sw)
    open(os.path.join(sw, "MyApp.exe"), "wb").close()
    open(os.path.join(sw, "WebView2Loader.dll"), "wb").close()
    kb = os.path.join(root, "keylib", "build")
    os.makedirs(kb)
    open(os.path.join(kb, "pkapp_key.dll"), "wb").close()
    rc_no_require = vendor_mod.run([], root=root)
    assert rc_no_require == 0
    assert "SKIP: shell-linux-x86_64" in capsys.readouterr().out
    assert not os.path.isdir(os.path.join(
        root, "pkapp", "pkapp", "_vendor", "shell-linux"))
    rc_require = vendor_mod.run(["--require", "shell-linux-x86_64"], root=root)
    assert rc_require == 2                       # --require 缺件契约 rc=2（既有语义）


def test_shell_linux_arm_arch_skip_local(vendor_mod, fake_repo, fake_wheel, capsys):
    """★阶段 5 前置★本地形态（WSL 仅构建 x86_64）：arm 双线记 SKIP 不失败；
    --require 命中 arm 条目才 rc=2（release.yml 全量 require 承载发布完整性）。"""
    fake_wheel(vendor_mod)
    os.remove(os.path.join(fake_repo, "shell-linux", "build", "aarch64", "myapp"))
    os.remove(os.path.join(fake_repo, "shell-linux", "build", "armv7l", "myapp"))
    assert vendor_mod.run(["--require", "shell-linux-x86_64"],
                          root=fake_repo) == 0
    out = capsys.readouterr().out
    assert "SKIP: shell-linux-aarch64" in out
    assert "SKIP: shell-linux-armv7l" in out
    assert not os.path.isdir(os.path.join(fake_repo, "pkapp", "pkapp", "_vendor",
                                          "shell-linux", "aarch64"))
    rc_require = vendor_mod.run(["--require", "shell-linux-armv7l"], root=fake_repo)
    assert rc_require == 2


def test_optional_skip_without_require(vendor_mod, fake_repo, fake_wheel, capsys):
    """可选条目（keylib-src）缺件：无 --require 时 rc=0，矩阵记 SKIP+原因。"""
    fake_wheel(vendor_mod)
    os.remove(os.path.join(fake_repo, "keylib", "src", "key.c"))
    assert vendor_mod.run([], root=fake_repo) == 0
    out = capsys.readouterr().out
    assert "[vendor] SKIP: keylib-src" in out


def test_require_gap_fails(vendor_mod, fake_repo, fake_wheel, capsys):
    """--require 命中 SKIP 条目 → rc=2 + 缺口清单（消灭静默的最后防线）。"""
    fake_wheel(vendor_mod)
    os.remove(os.path.join(fake_repo, "keylib", "src", "key.c"))
    assert vendor_mod.run(["--require", "keylib-src"], root=fake_repo) == 2
    out = capsys.readouterr().out
    assert "[vendor] --require 缺件" in out
    assert "keylib-src" in out


def test_require_unknown_entry_rejected(vendor_mod, fake_repo, fake_wheel, capsys):
    """--require 未知条目 → rc=2（闸门参数本身先过校验，防拼错静默放行）。"""
    assert vendor_mod.run(["--require", "keylib-android"], root=fake_repo) == 2
    out = capsys.readouterr().out
    assert "未知条目" in out


def test_hard_gate_missing_shell(vendor_mod, fake_repo, fake_wheel, capsys):
    """硬闸门条目缺件（MyApp.exe）→ 无 --require 也 rc=2（最小完整面前置）。"""
    fake_wheel(vendor_mod)                            # 防 pip 子进程真跑（闸门测试不测 wheel）
    os.remove(os.path.join(fake_repo, "shell-windows", "build", "MyApp.exe"))
    assert vendor_mod.run([], root=fake_repo) == 2
    out = capsys.readouterr().out
    assert "[vendor] SKIP: shell-windows" in out


def test_skip_clears_stale_artifacts(vendor_mod, fake_repo, fake_wheel, capsys):
    """★review 修复回归★：SKIP 条目必须清掉旧 _vendor 产物——上次收录成功、
    本次源缺失时，滞留旧件会照常进 wheel（静默陈旧），矩阵不可只是展示层。"""
    fake_wheel(vendor_mod)
    vroot = os.path.join(fake_repo, "pkapp", "pkapp", "_vendor")
    # 预放"上一次收录"的旧产物
    stale = {
        os.path.join(vroot, "shell", "MyApp.exe"),
        os.path.join(vroot, "shell-linux", "x86_64", "myapp"),
        os.path.join(vroot, "keylib", "windows", "pkapp_key.dll"),
        os.path.join(vroot, "keylib", "linux", "armv7l", "pkapp_key.so"),
        os.path.join(vroot, "keylib", "src", "key.c"),
        os.path.join(vroot, "shell-android", "app", "AndroidManifest.xml"),
    }
    for p in stale:
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "wb") as f:
            f.write(b"stale")
    # 源全部缺失（shell-windows / shell-linux-x86_64 / keylib-windows /
    # keylib-linux-armv7l / keylib-src / shell-android）
    os.remove(os.path.join(fake_repo, "shell-windows", "build", "MyApp.exe"))
    os.remove(os.path.join(fake_repo, "shell-linux", "build", "myapp"))
    os.remove(os.path.join(fake_repo, "keylib", "build", "pkapp_key.dll"))
    os.remove(os.path.join(fake_repo, "keylib", "build", "linux", "armv7l",
                           "pkapp_key.so"))
    os.remove(os.path.join(fake_repo, "keylib", "src", "key.c"))
    shutil.rmtree(os.path.join(fake_repo, "shell-android", "shell"))
    rc = vendor_mod.run([], root=fake_repo)
    assert rc == 2                                    # shell-windows 硬闸门拦截
    for p in stale:
        assert not os.path.exists(p), f"旧产物滞留: {p}"


def test_keylib_linux_anchor_missing_rejected(vendor_mod, fake_repo, fake_wheel,
                                              capsys):
    """linux keylib 无锚点字节 → 拒收 SKIP（patch_dll 定位前提失效，件源
    不对版——防错版 .so 静默进 wheel 后在用户 package 期才炸）。"""
    fake_wheel(vendor_mod)
    src = os.path.join(fake_repo, "keylib", "build", "linux", "x86_64",
                       "pkapp_key.so")
    with open(src, "wb") as f:
        f.write(b"\x7fELF-so-without-anchor-slot")
    assert vendor_mod.run([], root=fake_repo) == 0    # 可选条目，SKIP 不失败
    out = capsys.readouterr().out
    assert "SKIP: keylib-linux-x86_64" in out
    assert "无锚点字节" in out
    assert not os.path.isdir(os.path.join(fake_repo, "pkapp", "pkapp", "_vendor",
                                          "keylib", "linux", "x86_64"))
    rc = vendor_mod.run(["--require", "keylib-linux-x86_64"], root=fake_repo)
    assert rc == 2


def test_applocal_wheel_clears_stale_wheels(vendor_mod, fake_repo, monkeypatch):
    """★review 修复回归★：_build_applocal_wheel 必须先清 _vendor/wheels——
    applocal 版本 bump 后旧 wheel 滞留会打进 pkapp wheel（旧版 main() 有此清理，
    矩阵化重构时曾遗漏）。pip 步骤 monkeypatch 掉，专测清理行为。"""
    wheels_dir = os.path.join(fake_repo, "pkapp", "pkapp", "_vendor", "wheels")
    os.makedirs(wheels_dir, exist_ok=True)
    with open(os.path.join(wheels_dir, "applocal-0.0.9-py3-none-any.whl"), "wb") as f:
        f.write(b"stale-wheel")

    class _R:                                        # pip 假跑：成功、不产 wheel
        returncode = 0

    monkeypatch.setattr(vendor_mod.subprocess, "run", lambda *_a, **_k: _R())
    status, detail = vendor_mod._build_applocal_wheel(
        os.path.join(fake_repo, "pkapp", "pkapp", "_vendor"), fake_repo)
    assert status == "OK" and "0 wheel" in detail
    assert not os.path.isfile(os.path.join(wheels_dir,
                                           "applocal-0.0.9-py3-none-any.whl"))


def test_locate_dll_android_env_only(monkeypatch):
    """★H4★ locate_dll("android") 仅认 PKAPP_KEYLIB env——_vendor/仓库回退
    已移除（与 vendor.py 不收录 android 配套，fallback 链两端同时拆除）。"""
    from pkapp.packager import keylib

    monkeypatch.delenv("PKAPP_KEYLIB", raising=False)
    assert keylib.locate_dll("android") is None
    # env 指定（模式 B，用户明确意图）仍生效
    monkeypatch.setenv("PKAPP_KEYLIB", "C:/nonexistent/lib.so")
    assert keylib.locate_dll("android") is None
