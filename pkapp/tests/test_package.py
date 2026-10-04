"""pkapp package 冒烟：windows 缺 spk 报错 / 配对自检闸门（坏 spk 被拒，模式 A 出货防线）/
android 组装正例（monkeypatch gradle，APK 落 release/）/ 负例（spk 未入 APK 报错）。"""
import hashlib
import json
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


def _strip_android_package(proj):
    """模板已预填 package（com.example.myapp）→ 注释还原缺省态，供缺失分支测试。"""
    path = os.path.join(proj, "pkapp.toml")
    with open(path, encoding="utf-8") as f:
        txt = f.read()
    txt = txt.replace('package = "com.example.myapp"',
                      '# package = "com.example.myapp"', 1)
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
    """monkeypatch gradle：记录 -PpkappAppId/-PpkappIconRes/-PpkappAbis 注入；在壳工程产物位
    放一个假 APK（含/缺 assets/runtime.spk）。返回 captured 字典供断言。"""
    fake_apk = tmp_path / "fake.apk"
    with zipfile.ZipFile(fake_apk, "w") as zf:
        if with_asset:
            zf.writestr("assets/runtime.spk", spk_bytes)
        zf.writestr("classes.dex", b"dex-stub")
    captured = {}

    def fake_gradle(shell_dir, variant, app_id, label,
                    keystore=None, keystore_pass="", keystore_alias="",
                    icon_res=None, abis=()):
        captured.update(app_id=app_id, label=label, keystore=keystore,
                        keystore_pass=keystore_pass, keystore_alias=keystore_alias,
                        icon_res=icon_res, abis=abis)
        out_apk = os.path.join(shell_dir, "app", "build", "outputs", "apk", variant)
        os.makedirs(out_apk)
        name = f"app-{variant}.apk"
        if variant == "release" and not keystore:
            name = f"app-{variant}-unsigned.apk"     # gradle 对未签名 release 的产物名
        shutil.copyfile(fake_apk, os.path.join(out_apk, name))

    monkeypatch.setattr(apk_mod, "_run_gradle", fake_gradle)
    return captured


def _bare_template(tmp_path):
    """裸壳模板（★方案A★ 唯一形态）：纯源码，物化+注入由 mock 快照供给数据。"""
    t = tmp_path / "tpl"
    (t / "app" / "src" / "main").mkdir(parents=True)
    (t / "settings.gradle.kts").write_text("// s", encoding="utf-8")
    (t / "build.gradle.kts").write_text("// r", encoding="utf-8")
    (t / "app" / "build.gradle.kts").write_text("// a", encoding="utf-8")
    (t / "app" / "src" / "main" / "AndroidManifest.xml").write_text("<m/>",
                                                                    encoding="utf-8")
    return str(t)


def test_package_android_builds_apk(tmp_path, monkeypatch, mock_android_runtime):
    proj = _make_project(tmp_path)

    _write_spk(proj, "android")
    # spk 字节读回用于假 APK 内嵌（保持与源字节一致，过硬校验）
    with open(os.path.join(proj, "build", "platform-android", "runtime.spk"), "rb") as f:
        spk_bytes = f.read()
    captured = _fake_gradle(monkeypatch, tmp_path, with_asset=True, spk_bytes=spk_bytes)
    assert main(["package", "android", "--project", proj,
                 "--shell-dir", _bare_template(tmp_path)]) == 0
    assert captured["app_id"] == "com.example.myapp"      # -PpkappAppId 注入链（★v1.2★）
    assert captured["label"] == "myapp"                   # -PpkappLabel = app.name（★v1.2★）
    apk_path = os.path.join(proj, "release", "myapp-0.1.0-android-arm64_v8a.apk")
    assert os.path.isfile(apk_path)
    with zipfile.ZipFile(apk_path) as zf:
        assert zf.read("assets/runtime.spk") == spk_bytes


def test_package_android_icon_injected(tmp_path, monkeypatch, mock_android_runtime):
    """[platforms.android].icon → 相对路径解析 + 图标组生成 + -PpkappIconRes 注入链。"""
    from PIL import Image

    proj = _make_project(tmp_path)

    _add_android_icon(proj)
    _write_spk(proj, "android")
    with open(os.path.join(proj, "build", "platform-android", "runtime.spk"), "rb") as f:
        spk_bytes = f.read()
    captured = _fake_gradle(monkeypatch, tmp_path, with_asset=True, spk_bytes=spk_bytes)
    assert main(["package", "android", "--project", proj,
                 "--shell-dir", _bare_template(tmp_path)]) == 0
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


def test_package_android_icon_missing(tmp_path, monkeypatch, capsys,
                                      mock_android_runtime):
    """icon 指向不存在的文件 → fail-fast（exit 2，同 windows 图标前置检查语义）。"""
    proj = _make_project(tmp_path)

    _write_spk(proj, "android")
    _fake_gradle(monkeypatch, tmp_path, with_asset=True, spk_bytes=b"PK")
    path = os.path.join(proj, "pkapp.toml")
    with open(path, encoding="utf-8") as f:
        txt = f.read()
    txt = txt.replace('# icon = "icons/android/xplay.png"', 'icon = "icons/nope.png"', 1)
    with open(path, "w", encoding="utf-8") as f:
        f.write(txt)
    assert main(["package", "android", "--project", proj,
                 "--shell-dir", _bare_template(tmp_path)]) == 2
    assert "图标文件不存在" in capsys.readouterr().out


def test_package_android_icon_not_png(tmp_path, monkeypatch, capsys,
                                      mock_android_runtime):
    """icon 非位图（Pillow 无法识别）→ ApkError 拒绝组装。"""
    proj = _make_project(tmp_path)

    png = _add_android_icon(proj)
    with open(png, "wb") as f:
        f.write(b"this is not an image at all")
    _write_spk(proj, "android")
    _fake_gradle(monkeypatch, tmp_path, with_asset=True, spk_bytes=b"PK")
    assert main(["package", "android", "--project", proj,
                 "--shell-dir", _bare_template(tmp_path)]) == 1
    assert "图标" in capsys.readouterr().out


def test_package_android_requires_app_id(tmp_path, monkeypatch, capsys,
                                         mock_android_runtime):
    """未配 [platforms.android].package → 拒绝组装（固定共享 id 会同机互相顶替）。"""
    proj = _make_project(tmp_path)
    _strip_android_package(proj)          # 模板已预填 → 还原缺省态以覆盖缺失分支
    _write_spk(proj, "android")
    _fake_gradle(monkeypatch, tmp_path, with_asset=True, spk_bytes=b"PK")
    assert main(["package", "android", "--project", proj,
                 "--shell-dir", _bare_template(tmp_path)]) == 1
    assert "package 必填" in capsys.readouterr().out


def test_package_android_release_signed(tmp_path, monkeypatch, mock_android_runtime):
    """★v1.2★ release 签名链：env keystore+密码 → -PpkappKs* 注入 → release 产物。"""
    ks = tmp_path / "release.keystore"
    ks.write_bytes(b"ks-stub")
    proj = _make_project(tmp_path)

    _write_spk(proj, "android")
    with open(os.path.join(proj, "build", "platform-android", "runtime.spk"), "rb") as f:
        spk_bytes = f.read()
    captured = _fake_gradle(monkeypatch, tmp_path, with_asset=True, spk_bytes=spk_bytes)
    monkeypatch.setenv("PKAPP_KEYSTORE", str(ks))
    monkeypatch.setenv("PKAPP_KEYSTORE_PASS", "s3cret")
    monkeypatch.setenv("PKAPP_KEYSTORE_ALIAS", "mykey")
    assert main(["package", "android", "--project", proj, "--variant", "release",
                 "--shell-dir", _bare_template(tmp_path)]) == 0
    assert captured["keystore"] == str(ks)
    assert captured["keystore_pass"] == "s3cret"
    assert captured["keystore_alias"] == "mykey"
    assert os.path.isfile(os.path.join(
        proj, "release", "myapp-0.1.0-android-arm64_v8a.apk"))


def test_package_android_keystore_requires_pass(tmp_path, monkeypatch, capsys,
                                                mock_android_runtime):
    """★v1.2★ keystore 有路径无密码 → 拒绝（密码永不落文件,只走 env）。"""
    proj = _make_project(tmp_path)

    _write_spk(proj, "android")
    _fake_gradle(monkeypatch, tmp_path, with_asset=True, spk_bytes=b"PK")
    monkeypatch.setenv("PKAPP_KEYSTORE", str(tmp_path / "ks"))
    monkeypatch.delenv("PKAPP_KEYSTORE_PASS", raising=False)
    assert main(["package", "android", "--project", proj, "--variant", "release",
                 "--shell-dir", _bare_template(tmp_path)]) == 1
    assert "必须同时提供密码" in capsys.readouterr().out


def test_package_android_rejects_missing_asset(tmp_path, monkeypatch, capsys,
                                               mock_android_runtime):
    proj = _make_project(tmp_path)

    _write_spk(proj, "android")
    _fake_gradle(monkeypatch, tmp_path, with_asset=False, spk_bytes=b"")
    assert main(["package", "android", "--project", proj,
                 "--shell-dir", _bare_template(tmp_path)]) == 1
    out = capsys.readouterr().out
    assert "APK 组装失败" in out
    assert "未入 APK" in out


# ---- --arch：单 ABI 覆盖（build）+ build-meta 沿用/断言（package）----


def _mock_android_runtime_for(tmp_path, abis):
    """按指定 ABI 铺 mock android 快照（conftest.mock_android_runtime 的指定 abi 变体）。"""
    from pkapp import toolchain
    from pkapp.tools.mockkit import make_mock_android_runtime
    root = toolchain.managed_runtime_dir("android")
    make_mock_android_runtime(root, abis=abis)
    with open(os.path.join(root, "snapshot.toml"), "w", encoding="utf-8") as f:
        f.write('python_version = "3.12.14"\n')
    return root


def test_package_android_meta_abis_win_over_toml(tmp_path, monkeypatch, pkapp_cache):
    """build-meta.json（最后一次 build 记录）优先于 TOML：TOML 缺省 arm64 而记录 v7a
    → package 沿用 v7a——spk 按单 ABI 装配，package 的 ABI 跟随最后一次 build。"""
    _mock_android_runtime_for(tmp_path, ("armeabi-v7a",))
    proj = _make_project(tmp_path)

    _write_spk(proj, "android")
    with open(os.path.join(proj, "build", "platform-android", "build-meta.json"),
              "w", encoding="utf-8") as f:
        json.dump({"abis": ["armeabi-v7a"]}, f)
    with open(os.path.join(proj, "build", "platform-android", "runtime.spk"), "rb") as f:
        spk_bytes = f.read()
    captured = _fake_gradle(monkeypatch, tmp_path, with_asset=True, spk_bytes=spk_bytes)
    assert main(["package", "android", "--project", proj,
                 "--shell-dir", _bare_template(tmp_path)]) == 0
    assert captured["abis"] == ("armeabi-v7a",)
    assert os.path.isfile(os.path.join(
        proj, "release", "myapp-0.1.0-android-armeabi_v7a.apk"))


def test_package_android_arch_mismatch_rejected(tmp_path, monkeypatch, capsys):
    """--arch 与 build 记录不符 → fail-fast（拒绝产出壳/包 ABI 错配的静默坏包）。"""
    proj = _make_project(tmp_path)

    _write_spk(proj, "android")
    with open(os.path.join(proj, "build", "platform-android", "build-meta.json"),
              "w", encoding="utf-8") as f:
        json.dump({"abis": ["armeabi-v7a"]}, f)
    _fake_gradle(monkeypatch, tmp_path, with_asset=True, spk_bytes=b"PK")
    assert main(["package", "android", "--project", proj, "--arch", "arm64-v8a",
                 "--shell-dir", _bare_template(tmp_path)]) == 2
    assert "与 spk 构建记录不符" in capsys.readouterr().out


def test_package_arch_non_android_rejected(tmp_path, capsys):
    assert main(["package", "windows", "--project", str(tmp_path),
                 "--arch", "arm64-v8a"]) == 2
    assert "--arch 仅支持 android" in capsys.readouterr().out


def test_build_arch_non_android_rejected(tmp_path, capsys):
    assert main(["build", "windows", "--project", str(tmp_path),
                 "--arch", "arm64-v8a"]) == 2
    assert "--arch 仅支持 android" in capsys.readouterr().out


def test_build_arch_multi_value_rejected(tmp_path, capsys):
    assert main(["build", "android", "--project", str(tmp_path),
                 "--arch", "arm64-v8a,armeabi-v7a"]) == 2
    assert "单 ABI" in capsys.readouterr().out


def test_build_arch_override_records_meta(tmp_path, monkeypatch, pkapp_cache):
    """build --arch 覆盖 TOML（仅本次，不写回）+ build-meta.json 记录本次 ABI。"""
    proj = _make_project(tmp_path)
    toml_path = os.path.join(proj, "pkapp.toml")
    with open(toml_path, encoding="utf-8") as f:
        toml_before = f.read()

    from pkapp.packager import assemble as assemble_mod
    captured = {}

    def fake_build_spk(project, spec, platform, out_path, *,
                       private_key=None, wheels_dir=None):
        captured["abis"] = spec.android_abis
        os.makedirs(os.path.dirname(out_path), exist_ok=True)
        with zipfile.ZipFile(out_path, "w") as zf:
            zf.writestr("manifest.json", "{}")
        return {"spk_hash": "sha256:fake", "app_version": "0.1.0",
                "min_app_version": "0.1.0", "python_dll": "libpython3.12.so",
                "entry": "app.main:app", "applocal_version": "0.1.0",
                "signature": "unsigned"}

    monkeypatch.setattr(assemble_mod, "build_spk", fake_build_spk)
    assert main(["build", "android", "--project", proj, "--unsigned",
                 "--arch", "armeabi-v7a"]) == 0
    assert captured["abis"] == ("armeabi-v7a",)
    with open(os.path.join(proj, "build", "platform-android", "build-meta.json"),
              encoding="utf-8") as f:
        meta = json.load(f)
    assert meta["abis"] == ["armeabi-v7a"]
    # spk_sha256 = 写盘 spk 的文件级 sha256（package 配对闸门的比对基准）
    with open(os.path.join(proj, "build", "platform-android", "runtime.spk"), "rb") as f:
        spk_bytes = f.read()
    assert meta["spk_sha256"] == "sha256:" + hashlib.sha256(spk_bytes).hexdigest()
    with open(toml_path, encoding="utf-8") as f:
        assert f.read() == toml_before          # 覆盖不落盘，TOML 原样


def test_build_arch_unknown_abi_rejected(tmp_path, capsys):
    """--arch 非 NDK ABI（笔误如 x86_x64）→ fail-fast 并列出合法值（免得伪装成缺快照）。"""
    assert main(["build", "android", "--project", str(tmp_path),
                 "--arch", "x86_x64"]) == 2
    out = capsys.readouterr().out
    assert "不是合法 NDK ABI" in out and "x86_64" in out


def test_package_android_meta_spk_hash_mismatch_rejected(tmp_path, monkeypatch, capsys):
    """meta 的 spk_sha256 与磁盘 spk 不符（spk 被替换/meta 未跟上）→ 拒绝出包
    （android 壳不做 spk 验签，此闸门拦 ABI 错配的静默坏包）。"""
    proj = _make_project(tmp_path)

    _write_spk(proj, "android")
    with open(os.path.join(proj, "build", "platform-android", "build-meta.json"),
              "w", encoding="utf-8") as f:
        json.dump({"abis": ["arm64-v8a"], "spk_sha256": "sha256:" + "0" * 64}, f)
    _fake_gradle(monkeypatch, tmp_path, with_asset=True, spk_bytes=b"PK")
    assert main(["package", "android", "--project", proj,
                 "--shell-dir", _bare_template(tmp_path)]) == 2
    assert "不匹配" in capsys.readouterr().out
