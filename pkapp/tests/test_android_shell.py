"""★方案A★：壳模板物化 + 运行时注入（android_shell）单测 + build_apk 集成。

契约锚点：lib 前缀重命名（applocal/_ndk.py NdkExtFinder 消费 lib+原名）、
stdlib.zip ZIP_STORED（android libpython 无 zlib，D1 硬约束）、
指纹复用（gradle 增量）、缺快照 fail-fast（fetch 是唯一网络入口）。
"""
from __future__ import annotations

import json
import os
import time
import zipfile

import pytest

from pkapp.packager import android_shell
from pkapp.tools.mockkit import make_mock_android_runtime


def _bare_template(tmp_path):
    """最小裸模板（真实 shell-android/shell 的 gradle 骨架同构，无 jniLibs/assets）。"""
    t = tmp_path / "tpl"
    # exist_ok：同一 tmp_path 可重复铺设（test_prune_keeps_recent 迭代改写模板内容）
    (t / "app" / "src" / "main").mkdir(parents=True, exist_ok=True)
    (t / "settings.gradle.kts").write_text("// s", encoding="utf-8")
    (t / "build.gradle.kts").write_text("// r", encoding="utf-8")
    (t / "app" / "build.gradle.kts").write_text("// a", encoding="utf-8")
    (t / "app" / "src" / "main" / "AndroidManifest.xml").write_text("<m/>",
                                                                    encoding="utf-8")
    return str(t)


# ---------------------------------------------------------------- 注入布局契约
def test_inject_layout_contract(tmp_path, pkapp_cache):
    """顶层 .so 原样 + bundle modules→lib+原名 + stdlib.zip（ZIP_STORED）。"""
    rt = str(tmp_path / "rt")
    make_mock_android_runtime(rt, abis=("arm64-v8a",))
    work = android_shell.materialize(_bare_template(tmp_path), rt, ("arm64-v8a",))
    jni = os.path.join(work, "app", "src", "main", "jniLibs", "arm64-v8a")
    assert os.path.isfile(os.path.join(jni, "libpython3.12.so"))
    assert os.path.isfile(os.path.join(jni, "libssl_python.so"))
    assert os.path.isfile(os.path.join(jni, "lib_mock_ext.so"))   # lib+原名（_mock_ext）
    assert not os.path.isfile(os.path.join(jni, "libpythonbundle.so"))
    with zipfile.ZipFile(os.path.join(work, "app", "src", "main", "assets",
                                      "stdlib.zip")) as zf:
        assert zf.getinfo("os.py").compress_type == zipfile.ZIP_STORED
        assert zf.read("os.py") == b"a = 1\n"
    marker = json.load(open(os.path.join(work, ".pkapp-shell.json"), encoding="utf-8"))
    assert marker["abis"] == ["arm64-v8a"]


def test_materialize_reuses_fingerprint(tmp_path, pkapp_cache):
    """同指纹复用（不重拷、幂等）；模板内容变 → 新指纹新目录。"""
    rt = str(tmp_path / "rt")
    make_mock_android_runtime(rt, abis=("arm64-v8a",))
    tpl = _bare_template(tmp_path)
    w1 = android_shell.materialize(tpl, rt, ("arm64-v8a",))
    sentinel = os.path.join(w1, "sentinel.txt")
    with open(sentinel, "w", encoding="utf-8") as f:
        f.write("keep")
    w2 = android_shell.materialize(tpl, rt, ("arm64-v8a",))
    assert w1 == w2 and os.path.isfile(sentinel)
    with open(os.path.join(tpl, "build.gradle.kts"), "a", encoding="utf-8") as f:
        f.write("\n// changed\n")
    w3 = android_shell.materialize(tpl, rt, ("arm64-v8a",))
    assert w3 != w2 and not os.path.isfile(os.path.join(w3, "sentinel.txt"))


def test_prune_keeps_recent(tmp_path, pkapp_cache):
    """淘汰水位：仅保留最近 _KEEP_DIRS 个指纹目录，当前目录必在。

    copytree copystat 会让物化目录继承模板 mtime（生产侧由 materialize 写完 marker
    后 utime 恢复"物化时刻"语义）——测试显式逐个递增 mtime 保证时序断言确定性
    （真实时钟粒度在快速迭代下可能同刻度）。
    """
    rt = str(tmp_path / "rt")
    make_mock_android_runtime(rt, abis=("arm64-v8a",))
    roots = []
    for i in range(4):
        tpl = _bare_template(tmp_path)
        with open(os.path.join(tpl, "build.gradle.kts"), "a", encoding="utf-8") as f:
            f.write(f"\n// v{i}\n")
        roots.append(android_shell.materialize(tpl, rt, ("arm64-v8a",)))
        os.utime(roots[-1], (1_000_000.0 + i * 100,) * 2)
    work_root = os.path.dirname(roots[-1])
    alive = set(os.listdir(work_root))
    assert len(alive) == android_shell._KEEP_DIRS
    assert os.path.basename(roots[-1]) in alive
    assert os.path.basename(roots[-2]) in alive     # 时序次新者也在
    assert os.path.basename(roots[0]) not in alive  # 最旧被淘汰


def test_materialize_tolerates_corrupt_marker(tmp_path, pkapp_cache):
    """marker 半截（上次构建中断残留）→ 视作缓存 miss 重建，而非裸 JSONDecodeError。"""
    rt = str(tmp_path / "rt")
    make_mock_android_runtime(rt, abis=("arm64-v8a",))
    tpl = _bare_template(tmp_path)
    work = android_shell.materialize(tpl, rt, ("arm64-v8a",))
    with open(os.path.join(work, ".pkapp-shell.json"), "w", encoding="utf-8") as f:
        f.write('{"fingerprint": "trunc')
    assert android_shell.materialize(tpl, rt, ("arm64-v8a",)) == work   # 同指纹同目录
    marker = json.load(open(os.path.join(work, ".pkapp-shell.json"), encoding="utf-8"))
    assert marker["abis"] == ["arm64-v8a"]
    assert os.path.isfile(os.path.join(work, "app", "src", "main", "assets",
                                       "stdlib.zip"))


# ---------------------------------------------------------------- fail-fast
def test_materialize_requires_runtime(tmp_path, pkapp_cache):
    """裸模板 + 无运行时快照 → fail-fast 指向 fetch（package 不隐式联网）。"""
    with pytest.raises(android_shell.AndroidShellError, match="fetch"):
        android_shell.materialize(_bare_template(tmp_path), None, ("arm64-v8a",))


def test_materialize_requires_abi_dir(tmp_path, pkapp_cache):
    """声明的 abi 在快照缺席 → fail-fast。"""
    rt = str(tmp_path / "rt")
    make_mock_android_runtime(rt, abis=("arm64-v8a",))
    with pytest.raises(android_shell.AndroidShellError, match="x86_64"):
        android_shell.materialize(_bare_template(tmp_path), rt, ("x86_64",))


def test_materialize_requires_abis(tmp_path, pkapp_cache):
    """abis 为空 → fail-fast（注入无目标）。"""
    rt = str(tmp_path / "rt")
    make_mock_android_runtime(rt, abis=("arm64-v8a",))
    with pytest.raises(android_shell.AndroidShellError, match="abis"):
        android_shell.materialize(_bare_template(tmp_path), rt, ())


# ---------------------------------------------------------------- build_apk 集成
def _fake_gradle(monkeypatch):
    """记录 _run_gradle 入参；产出带 runtime.spk + 注入件的最小假 APK。"""
    from pkapp.packager import apk as apk_mod
    captured = {}

    def fake_gradle(shell, variant, app_id, label, keystore=None, keystore_pass="",
                    keystore_alias="", icon_res=None, abis=()):
        captured.update(shell=shell, variant=variant, app_id=app_id, abis=abis)
        out = os.path.join(shell, "app", "build", "outputs", "apk", variant)
        os.makedirs(out)
        with zipfile.ZipFile(os.path.join(out, f"app-{variant}.apk"), "w") as zf:
            zf.writestr("assets/runtime.spk", b"PK-spk-bytes")
            zf.writestr("lib/arm64-v8a/lib_mock_ext.so", b"\x7fELF")
            zf.writestr("classes.dex", b"dex")
    monkeypatch.setattr(apk_mod, "_run_gradle", fake_gradle)
    return captured


def test_build_apk_bare_template_end_to_end(tmp_path, monkeypatch, mock_android_runtime):
    """裸模板 + 托管快照 → 物化注入 → gradle（假）→ 验收落 release/；
    gradle 收到物化目录与 -PpkappAbis 注入。"""
    from pkapp.packager import apk as apk_mod

    captured = _fake_gradle(monkeypatch)
    proj = str(tmp_path / "proj")
    os.makedirs(proj)
    spk = os.path.join(proj, "runtime.spk")
    with open(spk, "wb") as f:
        f.write(b"PK-spk-bytes")
    apk_path = apk_mod.build_apk(proj, "proj", spk,
                                 shell_dir=_bare_template(tmp_path),
                                 app_id="com.example.proj", version="0.1.0",
                                 abis=("arm64-v8a",),
                                 runtime_dir=mock_android_runtime)
    assert os.path.isfile(apk_path)
    work = captured["shell"]
    assert os.path.basename(work).startswith("android-")            # 物化目录而非模板
    assert captured["abis"] == ("arm64-v8a",)
    assert os.path.isfile(os.path.join(work, "app", "src", "main", "jniLibs",
                                       "arm64-v8a", "libpython3.12.so"))
    assert os.path.isfile(os.path.join(work, "app", "src", "main", "assets",
                                       "stdlib.zip"))
    with zipfile.ZipFile(apk_path) as zf:
        assert zf.read("assets/runtime.spk") == b"PK-spk-bytes"     # 字节硬校验链路


def test_build_apk_bare_template_without_runtime(tmp_path, monkeypatch, pkapp_cache):
    """裸模板 + 快照缺失 → ApkError 指向 fetch（而非神秘 gradle 失败）。"""
    from pkapp.packager import apk as apk_mod

    _fake_gradle(monkeypatch)
    proj = str(tmp_path / "proj")
    os.makedirs(proj)
    spk = os.path.join(proj, "runtime.spk")
    with open(spk, "wb") as f:
        f.write(b"PK")
    with pytest.raises(apk_mod.ApkError, match="fetch"):
        apk_mod.build_apk(proj, "proj", spk, shell_dir=_bare_template(tmp_path),
                          app_id="com.example.proj", version="0.1.0",
                          abis=("arm64-v8a",), runtime_dir=None)


def test_build_apk_lock_contention_and_stale_takeover(tmp_path, monkeypatch,
                                                      mock_android_runtime):
    """共享物化目录互斥：新鲜锁 → ApkError 指向并发语义；崩溃残留陈旧锁 → 自愈接管。"""
    from pkapp.packager import apk as apk_mod

    _fake_gradle(monkeypatch)
    proj = str(tmp_path / "proj")
    os.makedirs(proj)
    spk = os.path.join(proj, "runtime.spk")
    with open(spk, "wb") as f:
        f.write(b"PK-spk-bytes")
    tpl = _bare_template(tmp_path)
    work = android_shell.materialize(tpl, mock_android_runtime, ("arm64-v8a",))
    lock = os.path.join(work, apk_mod._LOCK_NAME)
    with open(lock, "w", encoding="utf-8") as f:
        f.write("999999")
    kwargs = dict(shell_dir=tpl, app_id="com.example.proj", version="0.1.0",
                  abis=("arm64-v8a",), runtime_dir=mock_android_runtime)
    with pytest.raises(apk_mod.ApkError, match="占用"):
        apk_mod.build_apk(proj, "proj", spk, **kwargs)
    stale = time.time() - apk_mod._LOCK_STALE_S - 10
    os.utime(lock, (stale, stale))
    apk_path = apk_mod.build_apk(proj, "proj", spk, **kwargs)
    assert os.path.isfile(apk_path)
    assert not os.path.isfile(lock)     # 构建毕锁释放
