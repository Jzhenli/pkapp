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


def test_find_rcedit_fallback_chain(tmp_path, monkeypatch):
    """_find_rcedit 查找序：--rcedit > PKAPP_RCEDIT > 托管缓存 > PATH；
    PINS 无 rcedit pin 时 ToolchainError 被接住降级 PATH（不崩，可选增强契约）。"""
    from pkapp import toolchain
    from pkapp.commands.package import _find_rcedit

    monkeypatch.setenv("PKAPP_CACHE", str(tmp_path / "cache"))
    monkeypatch.delenv("PKAPP_RCEDIT", raising=False)
    exe = tmp_path / "my-rcedit.exe"
    exe.write_bytes(b"MZ")
    assert _find_rcedit(str(exe)) == str(exe)            # 显式文件优先

    managed = toolchain.rcedit_path()                    # 托管缓存命中
    os.makedirs(os.path.dirname(managed), exist_ok=True)
    shutil.copyfile(exe, managed)
    assert _find_rcedit(None) == managed

    monkeypatch.setattr(toolchain, "PINS", ())           # pin 缺失 → 接住降级
    assert _find_rcedit(None) == (shutil.which("rcedit") or shutil.which("rcedit-x64"))


def _add_android_package(proj):
    """android 组装前置：[platforms.android].package（★v1.2★ 起必填 = applicationId）。
    新模板平台段已实体化 → 精准替换注释行（追加会产生重复 TOML 表）。"""
    path = os.path.join(proj, "pkapp.toml")
    with open(path, encoding="utf-8") as f:
        txt = f.read()
    marker = '# package = "com.example.helloworld"'
    assert marker in txt, "create 模板 android package 注释行已变，请同步本测试"
    txt = txt.replace(marker, 'package = "com.example.myapp"', 1)
    with open(path, "w", encoding="utf-8") as f:
        f.write(txt)


def _add_android_icon(proj):
    """android 图标前置：Pillow 生成 432×432 实图（生成器需可解码）+ 启用模板 icon 注释行。"""
    from PIL import Image

    png = os.path.join(proj, "icon.png")
    Image.new("RGB", (432, 432), (180, 40, 40)).save(png)
    path = os.path.join(proj, "pkapp.toml")
    with open(path, encoding="utf-8") as f:
        txt = f.read()
    marker = '# icon = "icons/android/xplay.png"'
    assert marker in txt, "create 模板 android icon 注释行已变，请同步本测试"
    txt = txt.replace(marker, 'icon = "icon.png"', 1)
    with open(path, "w", encoding="utf-8") as f:
        f.write(txt)
    return png


def _fake_gradle(monkeypatch, tmp_path, *, with_asset, spk_bytes):
    """monkeypatch gradle：记录 -PpkappAppId/-PpkappIconRes 注入；在壳工程产物位放一个
    假 APK（含/缺 assets/runtime.spk）。返回 captured 字典供断言。"""
    fake_apk = tmp_path / "fake.apk"
    with zipfile.ZipFile(fake_apk, "w") as zf:
        if with_asset:
            zf.writestr("assets/runtime.spk", spk_bytes)
        zf.writestr("classes.dex", b"dex-stub")
    captured = {}

    def fake_gradle(shell_dir, variant, app_id, label,
                    keystore=None, keystore_pass="", keystore_alias="",
                    icon_res=None):
        captured.update(app_id=app_id, label=label, keystore=keystore,
                        keystore_pass=keystore_pass, keystore_alias=keystore_alias,
                        icon_res=icon_res)
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
    apk_path = os.path.join(proj, "release", "myapp-0.1.0-android-arm64_v8a.apk")
    assert os.path.isfile(apk_path)
    with zipfile.ZipFile(apk_path) as zf:
        assert zf.read("assets/runtime.spk") == spk_bytes


def test_package_android_icon_injected(tmp_path, monkeypatch):
    """[platforms.android].icon → 相对路径解析 + 图标组生成 + -PpkappIconRes 注入链。"""
    from PIL import Image

    proj = _make_project(tmp_path)
    _add_android_package(proj)
    _add_android_icon(proj)
    _write_spk(proj, "android")
    with open(os.path.join(proj, "build", "platform-android", "runtime.spk"), "rb") as f:
        spk_bytes = f.read()
    captured = _fake_gradle(monkeypatch, tmp_path, with_asset=True, spk_bytes=spk_bytes)
    assert main(["package", "android", "--project", proj,
                 "--shell-dir", _fake_shell(tmp_path)]) == 0
    res_dir = os.path.join(os.path.abspath(proj), "build", "platform-android", "icon-res")
    assert os.path.normcase(captured["icon_res"]) == os.path.normcase(res_dir)
    # 图标组：全密度传统位图 + 自适应前景层 + anydpi-v26 定义 + 背景色
    for bucket, legacy, canvas in (("mdpi", 48, 108), ("hdpi", 72, 162),
                                   ("xhdpi", 96, 216), ("xxhdpi", 144, 324),
                                   ("xxxhdpi", 192, 432)):
        assert Image.open(os.path.join(res_dir, f"mipmap-{bucket}", "ic_app.png")
                          ).size == (legacy, legacy)
        assert Image.open(os.path.join(
            res_dir, f"mipmap-{bucket}", "ic_app_foreground.png")).size == (canvas, canvas)
    xml = open(os.path.join(res_dir, "mipmap-anydpi-v26", "ic_app.xml"),
               encoding="utf-8").read()
    assert "@mipmap/ic_app_foreground" in xml and "@color/ic_app_background" in xml
    assert "B42828" in open(os.path.join(res_dir, "values", "ic_app.xml"),
                            encoding="utf-8").read()


def test_package_android_icon_missing(tmp_path, monkeypatch, capsys):
    """icon 指向不存在的文件 → fail-fast（exit 2，同 windows 图标前置检查语义）。"""
    proj = _make_project(tmp_path)
    _add_android_package(proj)
    _write_spk(proj, "android")
    _fake_gradle(monkeypatch, tmp_path, with_asset=True, spk_bytes=b"PK")
    path = os.path.join(proj, "pkapp.toml")
    with open(path, encoding="utf-8") as f:
        txt = f.read()
    txt = txt.replace('# icon = "icons/android/xplay.png"', 'icon = "icons/nope.png"', 1)
    with open(path, "w", encoding="utf-8") as f:
        f.write(txt)
    assert main(["package", "android", "--project", proj,
                 "--shell-dir", _fake_shell(tmp_path)]) == 2
    assert "图标文件不存在" in capsys.readouterr().out


def test_package_android_icon_not_png(tmp_path, monkeypatch, capsys):
    """icon 非位图（Pillow 无法识别）→ ApkError 拒绝组装。"""
    proj = _make_project(tmp_path)
    _add_android_package(proj)
    png = _add_android_icon(proj)
    with open(png, "wb") as f:
        f.write(b"this is not an image at all")
    _write_spk(proj, "android")
    _fake_gradle(monkeypatch, tmp_path, with_asset=True, spk_bytes=b"PK")
    assert main(["package", "android", "--project", proj,
                 "--shell-dir", _fake_shell(tmp_path)]) == 1
    assert "图标" in capsys.readouterr().out


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
    assert os.path.isfile(os.path.join(
        proj, "release", "myapp-0.1.0-android-arm64_v8a.apk"))


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
