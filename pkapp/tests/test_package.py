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


def _add_android_package(proj):
    """android 组装前置：[platforms.android].package（★v1.2★ 起必填 = applicationId）。"""
    with open(os.path.join(proj, "pkapp.toml"), "a", encoding="utf-8") as f:
        f.write('\n[platforms.android]\npackage = "com.example.myapp"\n')


def _fake_gradle(monkeypatch, tmp_path, *, with_asset, spk_bytes):
    """monkeypatch gradle：记录 -PpkappAppId 注入；在壳工程产物位放一个假 APK
    （含/缺 assets/runtime.spk）。返回 captured 字典供断言。"""
    fake_apk = tmp_path / "fake.apk"
    with zipfile.ZipFile(fake_apk, "w") as zf:
        if with_asset:
            zf.writestr("assets/runtime.spk", spk_bytes)
        zf.writestr("classes.dex", b"dex-stub")
    captured = {}

    def fake_gradle(shell_dir, variant, app_id, label,
                    keystore=None, keystore_pass="", keystore_alias=""):
        captured.update(app_id=app_id, label=label, keystore=keystore,
                        keystore_pass=keystore_pass, keystore_alias=keystore_alias)
        out_apk = os.path.join(shell_dir, "app", "build", "outputs", "apk", variant)
        os.makedirs(out_apk)
        name = f"app-{variant}.apk"
        if variant == "release" and not keystore:
            name = f"app-{variant}-unsigned.apk"     # gradle 对未签名 release 的产物名
        shutil.copyfile(fake_apk, os.path.join(out_apk, name))

    monkeypatch.setattr(apk_mod, "_run_gradle", fake_gradle)
    return captured


def _fake_shell(tmp_path):
    shell = tmp_path / "shell"
    (shell / "app" / "src" / "main" / "assets").mkdir(parents=True)
    (shell / "build.gradle.kts").write_text("// stub", encoding="utf-8")
    return str(shell)


def test_package_android_builds_apk(tmp_path, monkeypatch):
    proj = _make_project(tmp_path)
    _add_android_package(proj)
    _write_spk(proj, "android")
    # spk 字节读回用于假 APK 内嵌（保持与源字节一致，过硬校验）
    with open(os.path.join(proj, "build", "platform-android", "runtime.spk"), "rb") as f:
        spk_bytes = f.read()
    captured = _fake_gradle(monkeypatch, tmp_path, with_asset=True, spk_bytes=spk_bytes)
    assert main(["package", "android", "--project", proj,
                 "--shell-dir", _fake_shell(tmp_path)]) == 0
    assert captured["app_id"] == "com.example.myapp"      # -PpkappAppId 注入链（★v1.2★）
    assert captured["label"] == "myapp"                   # -PpkappLabel = app.name（★v1.2★）
    apk_path = os.path.join(proj, "release", "myapp.apk")
    assert os.path.isfile(apk_path)
    with zipfile.ZipFile(apk_path) as zf:
        assert zf.read("assets/runtime.spk") == spk_bytes


def test_package_android_requires_app_id(tmp_path, monkeypatch, capsys):
    """未配 [platforms.android].package → 拒绝组装（固定共享 id 会同机互相顶替）。"""
    proj = _make_project(tmp_path)
    _write_spk(proj, "android")
    _fake_gradle(monkeypatch, tmp_path, with_asset=True, spk_bytes=b"PK")
    assert main(["package", "android", "--project", proj,
                 "--shell-dir", _fake_shell(tmp_path)]) == 1
    assert "package 必填" in capsys.readouterr().out


def test_package_android_release_signed(tmp_path, monkeypatch):
    """★v1.2★ release 签名链：env keystore+密码 → -PpkappKs* 注入 → release 产物。"""
    ks = tmp_path / "release.keystore"
    ks.write_bytes(b"ks-stub")
    proj = _make_project(tmp_path)
    _add_android_package(proj)
    _write_spk(proj, "android")
    with open(os.path.join(proj, "build", "platform-android", "runtime.spk"), "rb") as f:
        spk_bytes = f.read()
    captured = _fake_gradle(monkeypatch, tmp_path, with_asset=True, spk_bytes=spk_bytes)
    monkeypatch.setenv("PKAPP_KEYSTORE", str(ks))
    monkeypatch.setenv("PKAPP_KEYSTORE_PASS", "s3cret")
    monkeypatch.setenv("PKAPP_KEYSTORE_ALIAS", "mykey")
    assert main(["package", "android", "--project", proj, "--variant", "release",
                 "--shell-dir", _fake_shell(tmp_path)]) == 0
    assert captured["keystore"] == str(ks)
    assert captured["keystore_pass"] == "s3cret"
    assert captured["keystore_alias"] == "mykey"
    assert os.path.isfile(os.path.join(proj, "release", "myapp.apk"))


def test_package_android_keystore_requires_pass(tmp_path, monkeypatch, capsys):
    """★v1.2★ keystore 有路径无密码 → 拒绝（密码永不落文件,只走 env）。"""
    proj = _make_project(tmp_path)
    _add_android_package(proj)
    _write_spk(proj, "android")
    _fake_gradle(monkeypatch, tmp_path, with_asset=True, spk_bytes=b"PK")
    monkeypatch.setenv("PKAPP_KEYSTORE", str(tmp_path / "ks"))
    monkeypatch.delenv("PKAPP_KEYSTORE_PASS", raising=False)
    assert main(["package", "android", "--project", proj, "--variant", "release",
                 "--shell-dir", _fake_shell(tmp_path)]) == 1
    assert "必须同时提供密码" in capsys.readouterr().out


def test_package_android_rejects_missing_asset(tmp_path, monkeypatch, capsys):
    proj = _make_project(tmp_path)
    _add_android_package(proj)
    _write_spk(proj, "android")
    _fake_gradle(monkeypatch, tmp_path, with_asset=False, spk_bytes=b"")
    assert main(["package", "android", "--project", proj,
                 "--shell-dir", _fake_shell(tmp_path)]) == 1
    out = capsys.readouterr().out
    assert "APK 组装失败" in out
    assert "未入 APK" in out
