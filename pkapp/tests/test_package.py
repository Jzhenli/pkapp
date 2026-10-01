"""pkapp package 冒烟：windows 缺 spk 报错 / 配对自检闸门（坏 spk 被拒，模式 A 出货防线）/
android 组装正例（monkeypatch gradle，APK 落 release/）/ 负例（spk 未入 APK 报错）。"""
import os
import shutil
import zipfile

import pytest

from pkapp.cli import main
from pkapp.packager import apk as apk_mod

_REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
_SHELL = os.path.join(_REPO, "shell-windows", "build", "MyApp.exe")


def _make_project(tmp_path):
    proj = str(tmp_path / "myapp")
    assert main(["create", "myapp", "--dir", proj, "--no-venv"]) == 0
    return proj


def _write_spk(proj, platform):
    spk_dir = os.path.join(proj, "build", f"platform-{platform}")
    os.makedirs(spk_dir)
    path = os.path.join(spk_dir, "runtime.spk")
    with open(path, "wb") as f:
        f.write(b"PK" + os.urandom(64))
    return path


def test_package_windows_requires_spk(tmp_path, capsys):
    proj = _make_project(tmp_path)
    assert main(["package", "windows", "--project", proj]) == 2
    assert "未找到 spk" in capsys.readouterr().out


@pytest.mark.skipif(not os.path.isfile(_SHELL), reason="预编译壳未构建")
def test_package_windows_gate_rejects_bad_spk(tmp_path, capsys):
    proj = _make_project(tmp_path)
    spk_dir = os.path.join(proj, "build", "platform-windows")
    os.makedirs(spk_dir)
    with open(os.path.join(spk_dir, "runtime.spk"), "wb") as f:
        f.write(b"not a zip")
    assert main(["package", "windows", "--project", proj]) == 2
    out = capsys.readouterr().out
    assert "配对自检失败" in out
    assert "PKAPP_SIGN_KEY" in out          # 引导到模式 A 的发布密钥构建方式


def test_package_android_requires_spk(tmp_path, capsys):
    proj = _make_project(tmp_path)
    assert main(["package", "android", "--project", proj]) == 2
    assert "先 pkapp build android" in capsys.readouterr().out


def _fake_gradle(monkeypatch, tmp_path, *, with_asset, spk_bytes):
    """monkeypatch gradle：在壳工程产物位放一个假 APK（含/缺 assets/runtime.spk）。"""
    fake_apk = tmp_path / "fake.apk"
    with zipfile.ZipFile(fake_apk, "w") as zf:
        if with_asset:
            zf.writestr("assets/runtime.spk", spk_bytes)
        zf.writestr("classes.dex", b"dex-stub")

    def fake_gradle(shell_dir, variant):
        out_apk = os.path.join(shell_dir, "app", "build", "outputs", "apk", variant)
        os.makedirs(out_apk)
        shutil.copyfile(fake_apk, os.path.join(out_apk, f"app-{variant}.apk"))

    monkeypatch.setattr(apk_mod, "_run_gradle", fake_gradle)


def _fake_shell(tmp_path):
    shell = tmp_path / "shell"
    (shell / "app" / "src" / "main" / "assets").mkdir(parents=True)
    (shell / "build.gradle.kts").write_text("// stub", encoding="utf-8")
    return str(shell)


def test_package_android_builds_apk(tmp_path, monkeypatch):
    proj = _make_project(tmp_path)
    _write_spk(proj, "android")
    # spk 字节读回用于假 APK 内嵌（保持与源字节一致，过硬校验）
    with open(os.path.join(proj, "build", "platform-android", "runtime.spk"), "rb") as f:
        spk_bytes = f.read()
    _fake_gradle(monkeypatch, tmp_path, with_asset=True, spk_bytes=spk_bytes)
    assert main(["package", "android", "--project", proj,
                 "--shell-dir", _fake_shell(tmp_path)]) == 0
    apk_path = os.path.join(proj, "release", "myapp.apk")
    assert os.path.isfile(apk_path)
    with zipfile.ZipFile(apk_path) as zf:
        assert zf.read("assets/runtime.spk") == spk_bytes


def test_package_android_rejects_missing_asset(tmp_path, monkeypatch, capsys):
    proj = _make_project(tmp_path)
    _write_spk(proj, "android")
    _fake_gradle(monkeypatch, tmp_path, with_asset=False, spk_bytes=b"")
    assert main(["package", "android", "--project", proj,
                 "--shell-dir", _fake_shell(tmp_path)]) == 1
    out = capsys.readouterr().out
    assert "APK 组装失败" in out
    assert "未入 APK" in out
