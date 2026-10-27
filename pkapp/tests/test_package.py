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
    # linux 段统一启用（python_version 声明 = package linux 声明闸门必需；
    # 对 windows/android 用例无害——load 白名单收段）
    with open(os.path.join(proj, "pkapp.toml"), "a", encoding="utf-8") as f:
        f.write('\n[platforms.linux]\npython_version = "3.12.14"\n')
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


def test_package_sidecar_extract_and_format1_rejected(tmp_path):
    """★P0★ 侧车提取：spk _integrity/* → exe 旁两文件；旧 format 1（无侧车）
    → RuntimeError 引导重 build（新壳拒收，组装期提前给可行动错误）。"""
    from pkapp.packager import integrity as ig
    from pkapp.packager.integrity import _extract_integrity_sidecar
    from pkapp.packager import sign as sign_mod
    from pkapp.packager import spk as spk_mod

    proj = _make_project(tmp_path)
    key = sign_mod.generate_keypair(os.path.join(proj, ".pkapp"))[0]
    stage = str(tmp_path / "stage")
    os.makedirs(stage)
    text = ig.render({"site-packages/deps.zip": "a" * 64})
    sig = ig.sign_manifest(text, key)
    spk_path = str(tmp_path / "runtime.spk")
    entries = sorted(
        [(spk_mod.MANIFEST_ENTRY, b"format_version = 2\nsignature = unsigned\n")]
        + ig.spk_sidecar_entries(text, sig),
        key=lambda e: e[0].encode("utf-8"))
    spk_mod.write_spk(spk_path, entries)
    _extract_integrity_sidecar(spk_path, stage)
    with open(os.path.join(stage, ig.SIDECAR_NAME), "rb") as f:
        assert f.read() == text
    with open(os.path.join(stage, ig.SIDECAR_SIG_NAME), "rb") as f:
        assert f.read() == sig.encode("ascii")

    old = str(tmp_path / "old.spk")   # format 1：无 _integrity/ 条目
    spk_mod.write_spk(old, [(spk_mod.MANIFEST_ENTRY, b"format_version = 1\n")])
    with pytest.raises(RuntimeError, match="重新 pkapp build windows"):
        _extract_integrity_sidecar(old, stage)


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
    from pkapp.packager.winshell import _find_rcedit

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
        os.makedirs(out_apk, exist_ok=True)   # 同物化目录多次构建（残件清理用例）
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


def _write_encrypted_spk(proj, code_key_id):
    """手造含 code_key_id 的 manifest 最小 spk（android 壳不做 spk 验签，
    _package_android 只读 manifest 判加密态——最小容器即可驱动 keylib 链）。"""
    from pkapp.packager import manifest as mf
    from pkapp.packager import spk as spk_mod

    fields = {k: "v" for k in mf.KEYS}
    fields["code_key_id"] = code_key_id
    spk_dir = os.path.join(proj, "build", "platform-android")
    os.makedirs(spk_dir, exist_ok=True)
    path = os.path.join(spk_dir, "runtime.spk")
    spk_mod.write_spk(path, [(spk_mod.MANIFEST_ENTRY,
                              mf.render(fields).encode("utf-8"))])
    return path


def test_package_android_encrypted_stages_keylib_so(tmp_path, monkeypatch,
                                                    mock_android_runtime,
                                                    android_keylib_so):
    """加密 android 包全链（§5.5）：spk manifest 带 code_key_id → _stage_keylib
    现场编译落位 .so（android 件 key_id 走 Python 镜像比对；无预制件退化，H4）
    → build_apk 拷入壳物化目录 jniLibs/<abi>/lib_pkapp_key.so（gradle mock，
    APK 组装链不受影响）。"""
    from pkapp.packager import keylib

    monkeypatch.delenv("PKAPP_KEYLIB", raising=False)    # 非模式 B：编译路径走文件落位
    master = hashlib.sha256(b"pkg-and").digest()         # ★档位1★ K 现场派生（不入项目）
    monkeypatch.setenv("PKAPP_MASTER_KEY", master.hex())
    key = keylib.derive_k_app(master, "myapp")           # app_id 与项目名同源
    proj = _make_project(tmp_path)
    spk_path = _write_encrypted_spk(proj, keylib.key_id_hex(key))
    with open(spk_path, "rb") as f:
        spk_bytes = f.read()
    _fake_gradle(monkeypatch, tmp_path, with_asset=True, spk_bytes=spk_bytes)
    assert main(["package", "android", "--project", proj,
                 "--shell-dir", _bare_template(tmp_path)]) == 0
    # 壳物化目录（<PKAPP_CACHE>/shells/android/android-<fp12>）内 jniLibs 落位
    from pkapp import toolchain
    jni_hits = []
    for dp, _dn, fns in os.walk(os.path.join(toolchain.cache_root(), "shells")):
        for fn in fns:
            if fn == "lib_pkapp_key.so":
                jni_hits.append(os.path.join(dp, fn))
    assert len(jni_hits) == 1
    jni_so = jni_hits[0]
    assert os.path.join("jniLibs", "arm64-v8a") in jni_so   # 单 ABI 与 spk 一致
    with open(jni_so, "rb") as f:
        data = f.read()
    assert keylib.ANCHOR not in data                        # compiled 件无锚点常量
    assert key in data                                      # K 编译期烧入（fixture 模拟）
    # 交付物 APK 内 spk 原样在 assets（加密包不走壳验签，APK 签名承担完整性）
    apk_path = os.path.join(proj, "release", "myapp-0.1.0-android-arm64_v8a.apk")
    with zipfile.ZipFile(apk_path) as zf:
        assert zf.read("assets/runtime.spk") == spk_bytes


def test_package_android_plaintext_clears_stale_keylib(tmp_path, monkeypatch,
                                                       mock_android_runtime,
                                                       android_keylib_so):
    """物化目录跨构建复用（指纹不含加密态）→ 明文构建（manifest 无 code_key_id）
    必须清掉上一次加密构建残留在 jniLibs 的 lib_pkapp_key.so——否则上个项目的
    K⊕MASK 随明文 APK 分发（G6 泄漏）。"""
    from pkapp.packager import keylib

    monkeypatch.delenv("PKAPP_KEYLIB", raising=False)
    master = hashlib.sha256(b"stale-k").digest()         # ★档位1★ K 现场派生
    monkeypatch.setenv("PKAPP_MASTER_KEY", master.hex())
    key = keylib.derive_k_app(master, "myapp")
    proj = _make_project(tmp_path)
    tpl = _bare_template(tmp_path)

    # ① 明文构建：物化目录建立，无 keylib 链
    spk_path = _write_spk(proj, "android")
    _fake_gradle(monkeypatch, tmp_path, with_asset=True,
                 spk_bytes=open(spk_path, "rb").read())
    assert main(["package", "android", "--project", proj, "--shell-dir", tpl]) == 0
    # ② 加密构建：同一物化目录 → jniLibs/<abi>/lib_pkapp_key.so 落位
    spk_path = _write_encrypted_spk(proj, keylib.key_id_hex(key))
    spk_bytes = open(spk_path, "rb").read()
    _fake_gradle(monkeypatch, tmp_path, with_asset=True, spk_bytes=spk_bytes)
    assert main(["package", "android", "--project", proj, "--shell-dir", tpl]) == 0
    from pkapp import toolchain
    jni_hits = [os.path.join(dp, fn)
                for dp, _dn, fns in os.walk(os.path.join(toolchain.cache_root(),
                                                         "shells"))
                for fn in fns if fn == "lib_pkapp_key.so"]
    assert len(jni_hits) == 1                      # 残件确实落过位
    jni_dir = os.path.dirname(jni_hits[0])
    # ③ 明文构建（回到同一物化目录）：残件必须被清掉
    with open(spk_path, "wb") as f:
        f.write(b"PK" + os.urandom(64))
    _fake_gradle(monkeypatch, tmp_path, with_asset=True,
                 spk_bytes=open(spk_path, "rb").read())
    assert main(["package", "android", "--project", proj, "--shell-dir", tpl]) == 0
    assert not os.path.isfile(os.path.join(jni_dir, "lib_pkapp_key.so"))


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
    # ★M3★ 文案泛化：windows 仍拒（--arch 仅支持 android/linux 平台）
    assert "--arch 仅支持 android/linux" in capsys.readouterr().out


def test_build_arch_multi_value_rejected(tmp_path, capsys):
    assert main(["build", "android", "--project", str(tmp_path),
                 "--arch", "arm64-v8a,armeabi-v7a"]) == 2
    assert "单键" in capsys.readouterr().out   # ★M3★ 文案泛化（android/linux 共用）


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
        captured["abis"] = spec.android.abis
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


# ---- ★M3 阶段 2★ linux 终产物（tar.gz：launcher + spk + 部署 ._pth + 侧车 + .service）----

def test_package_linux_requires_spk(tmp_path, capsys):
    proj = _make_project(tmp_path)
    assert main(["package", "linux", "--project", proj]) == 2
    assert "未找到 spk" in capsys.readouterr().out


def test_package_linux_no_launcher_hardfail(tmp_path, capsys, monkeypatch):
    """R-L19 双保险：launcher ELF 不可得 → 硬失败拒出包（绝不静默产出无壳 tar.gz）。

    ★M3 修正★finder 返回 None 直接钉死——原用例依赖"仓库无 shell-linux/build/myapp"
    的环境偶然（本地 WSL 构建 / CI vendor 落位后该前提即破）；finder 各分支解析
    另有 test_find_launcher_linux_resolution 覆盖。"""
    import pkapp.packager.linshell as linshell
    monkeypatch.setattr(linshell, "_find_launcher_linux", lambda *a, **k: (None, False))
    proj = _make_project(tmp_path)
    _write_spk(proj, "linux")
    assert main(["package", "linux", "--project", proj]) == 2
    out = capsys.readouterr().out
    assert "未找到 launcher ELF" in out
    assert "拒绝出包" in out
    assert not os.path.isdir(os.path.join(proj, "release"))


def test_find_launcher_linux_resolution(tmp_path, monkeypatch):
    """_find_launcher_linux 解析序：explicit > PKAPP_SHELL_ELF > 开发壳 >
    包内置 vendor；explicit 缺文件不静默回退；全链未命中 → (None, False)
    （R-L19 前提）。返回 (launcher, patchable)：explicit/env = 模式 B 用户管件
    （不补丁），开发壳/vendor = 模式 A 分发件（补丁）——winshell._find_shell 同口径。"""
    import pkapp.packager.linshell as linshell
    elf = tmp_path / "launcher"
    elf.write_bytes(b"\x7fELF")
    assert linshell._find_launcher_linux(str(elf), "x86_64", "myapp") == (str(elf), False)
    assert linshell._find_launcher_linux(str(tmp_path / "nope"), "x86_64", "myapp") == (None, False)
    monkeypatch.setenv("PKAPP_SHELL_ELF", str(elf))
    assert linshell._find_launcher_linux(None, "x86_64", "myapp") == (str(elf), False)
    monkeypatch.setenv("PKAPP_SHELL_ELF", str(tmp_path / "nope"))
    assert linshell._find_launcher_linux(None, "x86_64", "myapp") == (None, False)  # env 缺文件硬失败不落穿
    monkeypatch.delenv("PKAPP_SHELL_ELF", raising=False)
    monkeypatch.setattr("pkapp.vendor.launcher_elf", lambda a, n: None)
    assert linshell._find_launcher_linux(None, "x86_64", "zz-no-such-shell") == (None, False)


def _fake_launcher(tmp_path, pub_hex: str) -> str:
    """伪 launcher ELF：出厂 hex 常量在场（补丁精确锚命中形态）。"""
    from pkapp.packager.winshell import _SHELL_DEFAULT_PUB
    p = str(tmp_path / f"launcher-{pub_hex[:8]}")
    with open(p, "wb") as f:
        f.write(b"\x7fELF-payload-" + _SHELL_DEFAULT_PUB.encode("ascii")
                + b"-tail" + (pub_hex != _SHELL_DEFAULT_PUB).to_bytes(1, "big"))
    return p


def _make_signed_spk(proj, platform, key):
    """真 format 2 spk（manifest + _integrity 侧车随包，侧车提取闸门可过）。"""
    from pkapp.packager import integrity as ig
    from pkapp.packager import spk as spk_mod
    spk_dir = os.path.join(proj, "build", f"platform-{platform}")
    os.makedirs(spk_dir, exist_ok=True)
    text = ig.render({"app/main.py": "a" * 64})
    sig = ig.sign_manifest(text, key)
    path = os.path.join(spk_dir, "runtime.spk")
    entries = sorted(
        [(spk_mod.MANIFEST_ENTRY,
          b"format_version = 2\nname = \"myapp\"\nsignature = unsigned\n")]
        + ig.spk_sidecar_entries(text, sig), key=lambda e: e[0].encode("utf-8"))
    spk_mod.write_spk(path, entries)
    return path


def test_package_linux_golden(tmp_path, capsys, monkeypatch):
    """★M3★ linux tar.gz golden：成员/权限/._pth 四行（D-5）/.service（D-1+D-6）/
    公钥补丁命中（出厂锚→项目 pub）/侧车随包（D-4）/staging 焚毁/arch 产物名。
    模式 A 路径（finder 返回出厂锚件）——补丁逻辑主锚；模式 B 显式件见
    test_package_linux_modeb_skips_patch。"""
    import tarfile
    from pkapp.packager import sign as sign_mod
    from pkapp.packager import linshell, winshell

    proj = _make_project(tmp_path)
    key = sign_mod.generate_keypair(os.path.join(proj, ".pkapp"))[0]
    pub = sign_mod.public_key_hex(key)
    _make_signed_spk(proj, "linux", key)
    launcher = _fake_launcher(tmp_path, winshell._SHELL_DEFAULT_PUB)
    monkeypatch.setattr(linshell, "_find_launcher_linux",
                        lambda *a, **k: (launcher, True))   # 模式 A：开发壳/厂商件
    monkeypatch.setattr(linshell, "_shell_accepts", lambda *a, **k: (True, ""))

    assert main(["package", "linux", "--project", proj]) == 0
    out = capsys.readouterr().out
    assert "公钥已配对项目密钥" in out
    tar_path = os.path.join(proj, "release", "myapp-0.1.0-linux-x86_64.tar.gz")
    assert os.path.isfile(tar_path)
    with tarfile.open(tar_path) as tf:
        names = tf.getnames()
        assert names == ["myapp/myapp", "myapp/myapp.spk", "myapp/myapp._pth",
                         "myapp/myapp.service", "myapp/integrity.manifest",
                         "myapp/integrity.manifest.sig"]
        modes = {n: tf.getmember(n).mode for n in names}
        assert modes["myapp/myapp"] == 0o755
        assert modes["myapp/myapp.spk"] == 0o644
        pth = tf.extractfile("myapp/myapp._pth").read().decode()
        elf = tf.extractfile("myapp/myapp").read()
    assert pth == "_runtime/python312.zip\n_runtime/lib-dynload\n" \
                  "_runtime/site-packages/deps.zip\n_runtime/site-packages/loose\n"
    assert pub.encode("ascii") in elf                       # 补丁命中项目公钥
    assert winshell._SHELL_DEFAULT_PUB.encode("ascii") not in elf   # 出厂锚已替换
    svc = tarfile.open(tar_path).extractfile("myapp/myapp.service").read().decode()
    assert "ExecStart=/opt/myapp/myapp" in svc and "WatchdogSec=30" in svc
    assert not os.path.isdir(os.path.join(proj, "build", "staging-linux"))  # 成功即焚


def test_package_linux_nt_host_degrades_static_assert(tmp_path, capsys, monkeypatch):
    """★自检降级★（2026-10-27 wheel 实测：Windows host 执行 linux launcher ELF →
    WinError 193）：_shell_accepts 进程启动失败 → 降级静态配对断言（补丁公钥命中 +
    出厂锚清零）→ 正常出货并明示降级。真实验证场景锚：wheel 内置件 Windows host
    直出明文包（模式 A 补丁已先行落地，字节断言兜住补丁正确性）。"""
    import tarfile
    from pkapp.packager import sign as sign_mod
    from pkapp.packager import linshell, winshell

    proj = _make_project(tmp_path)
    key = sign_mod.generate_keypair(os.path.join(proj, ".pkapp"))[0]
    pub = sign_mod.public_key_hex(key)
    _make_signed_spk(proj, "linux", key)
    launcher = _fake_launcher(tmp_path, winshell._SHELL_DEFAULT_PUB)
    monkeypatch.setattr(linshell, "_find_launcher_linux",
                        lambda *a, **k: (launcher, True))
    monkeypatch.setattr(
        linshell, "_shell_accepts",
        lambda *a, **k: (False, "壳自检进程启动失败: [WinError 193] "
                                "%1 不是有效的 Win32 应用程序。"))

    assert main(["package", "linux", "--project", proj]) == 0
    out = capsys.readouterr().out
    assert "★自检降级★" in out and "静态配对断言通过" in out
    tar_path = os.path.join(proj, "release", "myapp-0.1.0-linux-x86_64.tar.gz")
    with tarfile.open(tar_path) as tf:
        elf = tf.extractfile("myapp/myapp").read()
    assert pub.encode("ascii") in elf                       # 静态断言基准即补丁事实
    assert winshell._SHELL_DEFAULT_PUB.encode("ascii") not in elf


def test_package_linux_exec_fail_without_key_hardfails(tmp_path, capsys,
                                                       monkeypatch):
    """自检降级不可用（模式 B 自管件——patched_pub=None）：进程启动失败 →
    静态断言无从比对基准 → 照旧拒出货 + 指路 WSL/CI（不带病降级）。"""
    from pkapp.packager import linshell

    proj = _make_project(tmp_path)
    _write_spk(proj, "linux")
    paired = str(tmp_path / "paired-launcher")
    with open(paired, "wb") as f:
        f.write(b"\x7fELF-payload-tail")
    monkeypatch.setattr(
        linshell, "_shell_accepts",
        lambda *a, **k: (False, "壳自检进程启动失败: [WinError 193] boom"))

    assert main(["package", "linux", "--project", proj, "--shell", paired]) == 2
    out = capsys.readouterr().out
    assert "静态配对断言不可用" in out and "WSL/CI" in out
    assert os.path.isdir(os.path.join(proj, "build", "staging-linux"))


def test_package_linux_static_assert_failure_hardfails(tmp_path, capsys,
                                                       monkeypatch):
    """降级静态断言不过（补丁未落——monkeypatch 掉 _patch_shell_pubkey 模拟）：
    补丁公钥零命中 + 出厂锚残留 → 拒出货（降级不放过坏补丁）。"""
    from pkapp.packager import sign as sign_mod
    from pkapp.packager import linshell, winshell

    proj = _make_project(tmp_path)
    key = sign_mod.generate_keypair(os.path.join(proj, ".pkapp"))[0]
    _make_signed_spk(proj, "linux", key)
    launcher = _fake_launcher(tmp_path, winshell._SHELL_DEFAULT_PUB)
    monkeypatch.setattr(linshell, "_find_launcher_linux",
                        lambda *a, **k: (launcher, True))
    monkeypatch.setattr(linshell, "_patch_shell_pubkey", lambda *a, **k: None)
    monkeypatch.setattr(
        linshell, "_shell_accepts",
        lambda *a, **k: (False, "壳自检进程启动失败: [WinError 193] boom"))

    assert main(["package", "linux", "--project", proj]) == 2
    out = capsys.readouterr().out
    assert "静态配对断言失败" in out
    assert "补丁公钥命中 0 处" in out and "出厂锚残留 1 处" in out
    assert os.path.isdir(os.path.join(proj, "build", "staging-linux"))


def test_package_linux_gate_rejects_unpaired(tmp_path, capsys, monkeypatch):
    """出货闸门：--selftest-spk 验不过 → 拒出包 + staging 保留现场（windows 同口径）。"""
    from pkapp.packager import sign as sign_mod
    from pkapp.packager import linshell, winshell

    proj = _make_project(tmp_path)
    other = sign_mod.generate_keypair(str(tmp_path / "otherkey"))[0]   # 他钥签名
    _make_signed_spk(proj, "linux", other)
    launcher = _fake_launcher(tmp_path, winshell._SHELL_DEFAULT_PUB)
    monkeypatch.setattr(linshell, "_shell_accepts", lambda *a, **k: (False, "bad sig"))
    assert main(["package", "linux", "--project", proj, "--shell", launcher]) == 2
    out = capsys.readouterr().out
    assert "配对自检失败" in out
    assert os.path.isdir(os.path.join(proj, "build", "staging-linux"))


def test_package_linux_modeb_skips_patch(tmp_path, capsys, monkeypatch):
    """模式 B（显式 --shell 配对件，公钥编译期自定）：公钥补丁跳过不阻断，
    配对自检兜底通过 → 正常出货（真实验证场景锚：build.sh <AppName> <pub> 件）。"""
    import tarfile
    from pkapp.packager import sign as sign_mod
    from pkapp.packager import linshell

    proj = _make_project(tmp_path)
    key = sign_mod.generate_keypair(os.path.join(proj, ".pkapp"))[0]
    pub = sign_mod.public_key_hex(key)
    _make_signed_spk(proj, "linux", key)
    # 伪件内嵌项目 pub（64-hex 唯一段、无出厂锚——模式 B 形态）
    paired = str(tmp_path / "paired-launcher")
    with open(paired, "wb") as f:
        f.write(b"\x7fELF-payload-" + pub.encode("ascii") + b"-tail")
    monkeypatch.setattr(linshell, "_shell_accepts", lambda *a, **k: (True, ""))

    assert main(["package", "linux", "--project", proj, "--shell", paired]) == 0
    out = capsys.readouterr().out
    assert "模式 B" in out and "补丁跳过" in out
    assert "公钥已配对" not in out                          # 未走补丁
    tar_path = os.path.join(proj, "release", "myapp-0.1.0-linux-x86_64.tar.gz")
    with tarfile.open(tar_path) as tf:
        elf = tf.extractfile("myapp/myapp").read()
    assert pub.encode("ascii") in elf                       # 内嵌公钥原样保留
