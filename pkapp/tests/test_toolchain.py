"""toolchain（pkapp fetch）：下载校验 / 两态解压 / --from 导入 / snapshot.toml / 路径推导。

全部经 fetcher 注入（零联网）；PINS 以小 fixture 替换（monkeypatch），压缩包现场构造。
"""
import os
import shutil
import tarfile
import threading
import time
import zipfile

import pytest

from pkapp import toolchain
from pkapp.toolchain import Pin, ToolchainError

try:
    import tomllib
except ModuleNotFoundError:  # Python < 3.11
    import tomli as tomllib


# ---------------------------------------------------------------- 压缩包构造器
def _mk_zip(path, inner="inner-dir"):
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr(f"{inner}/a.txt", "hello")
        zf.writestr(f"{inner}/sub/b.txt", "world")
    return _sha(path)


def _mk_tar(path, entries):
    """rootless tar：条目名形如 ./libpython3.12.so（flet python-build 形态）。"""
    with tarfile.open(path, "w:gz") as tf:
        for name, data in entries.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            import io
            tf.addfile(info, io.BytesIO(data))
    return _sha(path)


def _sha(path):
    import hashlib
    h = hashlib.sha256()
    with open(path, "rb") as f:
        h.update(f.read())
    return h.hexdigest()


def _fetcher_by_name(src_map):
    """注入下载器：按 URL 尾段（pin.filename 语义）拷贝本地压缩包到 .part。"""
    def fetch(url, part):
        for tail, src in src_map.items():
            if url.endswith(tail):
                shutil.copyfile(src, part)
                return
        raise ToolchainError(f"fixture fetcher: 未预置 {url}")
    return fetch


def _zip_pin(pid, filename, url, sha, *, rename="", dest_parent="pkg"):
    return Pin(id=pid, platform="windows", filename=filename, urls=(url,),
               sha256=sha, kind="zip", dest_parent=dest_parent, inner_rename=rename)


# ---------------------------------------------------------------- 纯函数 / 环境
def test_apply_mirror(tmp_path, monkeypatch):
    monkeypatch.delenv("PKAPP_MIRROR_GITHUB", raising=False)
    monkeypatch.delenv("PKAPP_MIRROR_GOOGLE", raising=False)
    monkeypatch.delenv("PKAPP_MIRROR_GRADLE", raising=False)
    url = "https://github.com/astral-sh/x.tar.gz"
    assert toolchain.apply_mirror(url) == url            # 无 env → 原样
    monkeypatch.setenv("PKAPP_MIRROR_GITHUB", "https://ghfast.top")
    assert toolchain.apply_mirror(url) == "https://ghfast.top/astral-sh/x.tar.gz"
    monkeypatch.setenv("PKAPP_MIRROR_GRADLE", "https://mirrors.cloud.tencent.com/gradle/")
    assert toolchain.apply_mirror("https://services.gradle.org/distributions/g.zip") == \
        "https://mirrors.cloud.tencent.com/gradle/distributions/g.zip"
    assert toolchain.apply_mirror("https://dl.google.com/android/repository/x.zip") == \
        "https://dl.google.com/android/repository/x.zip"  # 未配 google → 原样


def test_cache_root_env_priority(tmp_path, monkeypatch):
    cache = str(tmp_path / "c1")
    monkeypatch.setenv("PKAPP_CACHE", cache)
    assert toolchain.cache_root() == cache
    monkeypatch.delenv("PKAPP_CACHE")
    monkeypatch.delenv("LOCALAPPDATA", raising=False)
    assert toolchain.cache_root() == os.path.join(os.path.expanduser("~"), ".cache", "pkapp")


# ---------------------------------------------------------------- download
def test_download_sha_mismatch_deletes_part(tmp_path):
    dl = tmp_path / "dl"
    dl.mkdir()
    pin = _zip_pin("p1", "a.zip", "https://example.test/a.zip", "0" * 64)
    junk = tmp_path / "junk.zip"
    junk.write_bytes(b"not the archive")
    with pytest.raises(ToolchainError, match="sha256 校验失败"):
        toolchain.download(pin, str(dl), _fetcher_by_name({"a.zip": str(junk)}))
    assert not list(dl.iterdir())                        # .part 已删，不落半件


def test_download_unverified_prints_measured_hash(tmp_path, capsys):
    dl = tmp_path / "dl"
    dl.mkdir()
    junk = tmp_path / "junk.zip"
    junk.write_bytes(b"PK-unverified")
    pin = _zip_pin("p2", "b.zip", "https://example.test/b.zip", "")
    got = toolchain.download(pin, str(dl), _fetcher_by_name({"b.zip": str(junk)}))
    assert got == str(dl / "b.zip")
    out = capsys.readouterr().out
    assert "实测" in out and _sha(str(junk)) in out      # 提示回填实测哈希


def test_download_http_exception_wrapped(tmp_path):
    """IncompleteRead（HTTPException，非 OSError 子类）同样包装成 ToolchainError 且不留 .part。"""
    import http.client
    dl = tmp_path / "dl"
    dl.mkdir()
    pin = _zip_pin("p2b", "x.zip", "https://example.test/x.zip", "")

    def flaky(url, part):
        open(part, "wb").close()
        raise http.client.IncompleteRead(b"partial")

    with pytest.raises(ToolchainError, match="下载失败"):
        toolchain.download(pin, str(dl), flaky)
    assert not list(dl.iterdir())


def test_download_skips_when_cached(tmp_path):
    dl = tmp_path / "dl"
    dl.mkdir()
    src = tmp_path / "c.zip"
    sha = _mk_zip(str(src))
    (dl / "c.zip").write_bytes(src.read_bytes())
    pin = _zip_pin("p3", "c.zip", "https://example.test/c.zip", sha)

    def boom(url, part):                                 # 命中缓存 → 下载器不得被调
        raise AssertionError("should not download")

    assert toolchain.download(pin, str(dl), boom) == str(dl / "c.zip")


# ---------------------------------------------------------------- import_from_dir
def test_import_from_dir_match_and_ignore(tmp_path):
    src = tmp_path / "from"
    src.mkdir()
    good = tmp_path / "good.zip"
    sha = _mk_zip(str(good))
    (src / "pin.zip").write_bytes(good.read_bytes())
    (src / "cmdtools.zip").write_bytes(b"not-a-pin")     # 不在 PINS → 天然忽略
    (src / "bad.zip").write_bytes(b"corrupt")            # 哈希不符 → 忽略
    dl = tmp_path / "dl"
    dl.mkdir()
    pins = (_zip_pin("p4", "pin.zip", "https://example.test/pin.zip", sha),
            _zip_pin("p5", "bad.zip", "https://example.test/bad.zip", "1" * 64))
    imported = toolchain.import_from_dir(str(src), str(dl), pins)
    assert imported == ["p4"]
    assert (dl / "pin.zip").read_bytes() == good.read_bytes()
    assert not (dl / "bad.zip").exists()
    assert not (dl / "cmdtools.zip").exists()


# ---------------------------------------------------------------- fetch / 两态解压
def _pins_for_fetch(tmp_path):
    a = tmp_path / "a.zip"
    sha_a = _mk_zip(str(a), inner="gradle-8.9")
    b = tmp_path / "b.zip"
    sha_b = _mk_zip(str(b), inner="whatever")
    t = tmp_path / "t.tar.gz"
    sha_t = _mk_tar(str(t), {"./libpython3.12.so": b"\x7fELF",
                             "./libpythonbundle.so": b"PK-bundle"})
    pins = (
        _zip_pin("gradle-8.9", "gradle-8.9-bin.zip", "https://example.test/gradle-8.9-bin.zip",
                 sha_a, rename="", dest_parent="android"),            # 保留内层名
        _zip_pin("renamed", "b.zip", "https://example.test/b.zip",
                 sha_b, rename="35.0.0", dest_parent="android/sdk/build-tools"),  # 重命名
        Pin(id="py-3.12.14-arm64-v8a", platform="windows", filename="t.tar.gz",
            urls=("https://example.test/t.tar.gz",), sha256=sha_t, kind="tar.gz",
            dest_parent="runtimes/py-3.12.14/arm64-v8a", rootless=True),  # rootless
    )
    src_map = {"gradle-8.9-bin.zip": str(a), "b.zip": str(b), "t.tar.gz": str(t)}
    return pins, src_map


def test_fetch_installs_two_states(tmp_path, monkeypatch):
    monkeypatch.setenv("PKAPP_CACHE", str(tmp_path / "cache"))
    pins, src_map = _pins_for_fetch(tmp_path)
    monkeypatch.setattr(toolchain, "PINS", pins)
    assert toolchain.fetch("windows", fetcher=_fetcher_by_name(src_map)) == 0

    cache = tmp_path / "cache"
    # ① zip 保留内层名
    assert (cache / "android" / "gradle-8.9" / "a.txt").read_text() == "hello"
    # ② zip 重命名内层目录
    assert (cache / "android" / "sdk" / "build-tools" / "35.0.0" / "a.txt").is_file()
    # ③ rootless tar 直接落 abi 目录
    assert (cache / "runtimes" / "py-3.12.14" / "arm64-v8a" / "libpython3.12.so").read_bytes() \
        == b"\x7fELF"
    # ④ snapshot.toml：python_version + 分节 pins（id/url/sha256/fetched_at）
    snap = tomllib.load(open(cache / "android" / "gradle-8.9" / "snapshot.toml", "rb"))
    assert snap["python_version"] == toolchain.PYTHON_VERSION
    assert snap["pins"]["gradle-8.9"]["sha256"] == _sha(str(tmp_path / "a.zip"))
    assert snap["pins"]["gradle-8.9"]["fetched_at"]
    # ⑤ 下载暂存进 dl/
    assert (cache / "dl" / "b.zip").is_file()


def test_fetch_idempotent_second_run_skips(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("PKAPP_CACHE", str(tmp_path / "cache"))
    pins, src_map = _pins_for_fetch(tmp_path)
    monkeypatch.setattr(toolchain, "PINS", pins)
    assert toolchain.fetch("windows", fetcher=_fetcher_by_name(src_map)) == 0
    calls = []

    def counting(url, part):
        calls.append(url)
        _fetcher_by_name(src_map)(url, part)

    assert toolchain.fetch("windows", fetcher=counting) == 0
    assert calls == []                                   # dl/ 命中 → 零下载
    out = capsys.readouterr().out
    assert out.count("已就位") == len(pins)               # 安装层幂等跳过


def test_install_replace_retries_transient_lock(tmp_path, monkeypatch):
    """os.replace 撞瞬态句柄锁（WinError 5，Defender 扫新解压目录实测复现）→ 重试后成功。"""
    monkeypatch.setenv("PKAPP_CACHE", str(tmp_path / "cache"))
    pins, src_map = _pins_for_fetch(tmp_path)
    monkeypatch.setattr(toolchain, "PINS", pins)
    real_replace, calls = os.replace, []

    def flaky(src, dst):
        if src.endswith("gradle-8.9"):                   # 仅命中安装 rename（.part 落盘不受扰）
            calls.append(src)
            if len(calls) == 1:
                raise PermissionError(5, "拒绝访问。")
        real_replace(src, dst)

    monkeypatch.setattr(toolchain.os, "replace", flaky)
    assert toolchain.fetch("windows", fetcher=_fetcher_by_name(src_map)) == 0
    assert len(calls) == 2                               # 首撞锁 → 重试第二次成功
    assert (tmp_path / "cache" / "android" / "gradle-8.9" / "a.txt").read_text() == "hello"


def test_fetch_root_multi_entry_zip(tmp_path, monkeypatch):
    """cmake 直链包形态：zip 根级多条目（无内层目录）→ tmp 即组件根，按
    inner_rename 落位（android/sdk/cmake/3.22.1）；缺 inner_rename → 报错。"""
    monkeypatch.setenv("PKAPP_CACHE", str(tmp_path / "cache"))
    z = tmp_path / "cmake.zip"
    with zipfile.ZipFile(z, "w") as zf:
        zf.writestr("bin/cmake.exe", b"cmake")
        zf.writestr("share/cmake-3.22/x.txt", b"x")
        zf.writestr("source.properties", "Pkg.Revision=3.22.1")
    sha = _sha(str(z))
    pins = (_zip_pin("cmake-3.22.1", "cmake.zip", "https://example.test/cmake.zip",
                     sha, rename="3.22.1", dest_parent="android/sdk/cmake"),)
    monkeypatch.setattr(toolchain, "PINS", pins)
    cache = tmp_path / "cache"
    assert toolchain.fetch("windows", fetcher=_fetcher_by_name({"cmake.zip": str(z)})) == 0
    comp = cache / "android" / "sdk" / "cmake" / "3.22.1"
    assert (comp / "bin" / "cmake.exe").read_bytes() == b"cmake"
    assert (comp / "source.properties").is_file()
    snap = tomllib.load(open(comp / "snapshot.toml", "rb"))
    assert snap["pins"]["cmake-3.22.1"]["sha256"] == sha
    # 缺 inner_rename → 明确报错（内层名无从推断）
    bad = (_zip_pin("cmake-bad", "cmake.zip", "https://example.test/cmake.zip",
                    sha, rename="", dest_parent="android/sdk/cmake"),)
    monkeypatch.setattr(toolchain, "PINS", bad)
    with pytest.raises(ToolchainError, match="inner_rename"):
        toolchain.fetch("windows", fetcher=_fetcher_by_name({"cmake.zip": str(z)}))


def test_download_parallel_peak_concurrency(tmp_path, monkeypatch):
    """多件缺失 → 线程池并发（并发峰值 >= 2），全部落盘。"""
    monkeypatch.setenv("PKAPP_CACHE", str(tmp_path / "cache"))
    src_map = {}
    for n in "abc":
        _mk_zip(str(tmp_path / f"{n}.zip"), inner=f"d{n}")
        src_map[f"{n}.zip"] = str(tmp_path / f"{n}.zip")
    pins = tuple(
        _zip_pin(f"p{i}", f"{n}.zip", f"https://example.test/{n}.zip", "")
        for i, n in enumerate("abc"))
    monkeypatch.setattr(toolchain, "PINS", pins)

    state = {"active": 0, "peak": 0}
    lock = threading.Lock()

    def slow_fetch(url, part):
        with lock:
            state["active"] += 1
            state["peak"] = max(state["peak"], state["active"])
        time.sleep(0.3)
        with lock:
            state["active"] -= 1
        _fetcher_by_name(src_map)(url, part)

    assert toolchain.fetch("windows", fetcher=slow_fetch) == 0
    assert state["peak"] >= 2                              # 并发确实发生
    cache = tmp_path / "cache" / "dl"
    assert all((cache / f"{n}.zip").is_file() for n in "abc")


def test_download_parallel_failure_aggregates(tmp_path, monkeypatch):
    """并发池任一失败：等全部收尾后汇总报错（含失败包名），成功件照常落盘。"""
    monkeypatch.setenv("PKAPP_CACHE", str(tmp_path / "cache"))
    a, b = tmp_path / "a.zip", tmp_path / "b.zip"
    _mk_zip(str(a), inner="da")
    _mk_zip(str(b), inner="db")
    pins = (_zip_pin("p0", "a.zip", "https://example.test/a.zip", ""),
            _zip_pin("p1", "b.zip", "https://example.test/b.zip", ""))
    monkeypatch.setattr(toolchain, "PINS", pins)

    def half_broken(url, part):
        if url.endswith("a.zip"):
            shutil.copyfile(str(a), part)
            return
        raise ToolchainError("模拟网络中断")

    with pytest.raises(ToolchainError, match="b.zip"):
        toolchain.fetch("windows", fetcher=half_broken)
    assert (tmp_path / "cache" / "dl" / "a.zip").is_file()          # 成功件保留
    assert not (tmp_path / "cache" / "dl" / "b.zip.part").exists()  # 失败不留半件


def test_fetch_rootless_reinstall_clears_stale(tmp_path, monkeypatch):
    """rootless 重装（dest 在但 snapshot 缺条目）先清旧目录，防陈旧文件残留。"""
    monkeypatch.setenv("PKAPP_CACHE", str(tmp_path / "cache"))
    t = tmp_path / "t.tar.gz"
    sha = _mk_tar(str(t), {"./libpython3.12.so": b"new"})
    pins = (Pin(id="py-3.12.14-arm64-v8a", platform="windows", filename="t.tar.gz",
                urls=("https://example.test/t.tar.gz",), sha256=sha, kind="tar.gz",
                dest_parent="runtimes/py-3.12.14/arm64-v8a", rootless=True),)
    monkeypatch.setattr(toolchain, "PINS", pins)
    stale = tmp_path / "cache" / "runtimes" / "py-3.12.14" / "arm64-v8a"
    stale.mkdir(parents=True)
    (stale / "stale-old.so").write_bytes(b"old")
    assert toolchain.fetch("windows", fetcher=_fetcher_by_name({"t.tar.gz": str(t)})) == 0
    assert (stale / "libpython3.12.so").read_bytes() == b"new"
    assert not (stale / "stale-old.so").exists()


def test_fetch_rootless_shared_snapshot(tmp_path, monkeypatch):
    """py-android 两 pin 共享父目录 snapshot.toml：分节共存互不覆盖。"""
    monkeypatch.setenv("PKAPP_CACHE", str(tmp_path / "cache"))
    t1 = tmp_path / "t1.tar.gz"
    sha1 = _mk_tar(str(t1), {"./libpython3.12.so": b"a"})
    t2 = tmp_path / "t2.tar.gz"
    sha2 = _mk_tar(str(t2), {"./libpython3.12.so": b"b"})
    pins = (
        Pin(id="py-3.12.14-arm64-v8a", platform="windows", filename="t1.tar.gz",
            urls=("https://example.test/t1.tar.gz",), sha256=sha1, kind="tar.gz",
            dest_parent="runtimes/py-3.12.14/arm64-v8a", rootless=True),
        Pin(id="py-3.12.14-x86_64", platform="windows", filename="t2.tar.gz",
            urls=("https://example.test/t2.tar.gz",), sha256=sha2, kind="tar.gz",
            dest_parent="runtimes/py-3.12.14/x86_64", rootless=True),
    )
    monkeypatch.setattr(toolchain, "PINS", pins)
    src_map = {"t1.tar.gz": str(t1), "t2.tar.gz": str(t2)}
    assert toolchain.fetch("windows", fetcher=_fetcher_by_name(src_map)) == 0
    snap = tomllib.load(open(tmp_path / "cache" / "runtimes" / "py-3.12.14" / "snapshot.toml",
                             "rb"))
    assert set(snap["pins"]) == {"py-3.12.14-arm64-v8a", "py-3.12.14-x86_64"}
    assert snap["pins"]["py-3.12.14-x86_64"]["sha256"] == sha2


def test_fetch_zip_slip_rejected(tmp_path, monkeypatch):
    monkeypatch.setenv("PKAPP_CACHE", str(tmp_path / "cache"))
    evil = tmp_path / "evil.zip"
    with zipfile.ZipFile(evil, "w") as zf:
        zf.writestr("../escape.txt", "pwned")
    pins = (_zip_pin("evil", "evil.zip", "https://example.test/evil.zip",
                     _sha(str(evil))),)
    monkeypatch.setattr(toolchain, "PINS", pins)
    with pytest.raises(ToolchainError, match="越界"):
        toolchain.fetch("windows", fetcher=_fetcher_by_name({"evil.zip": str(evil)}))


def test_fetch_from_dir_offline(tmp_path, monkeypatch):
    """--from 离线导入 + 缺件 fail-fast（build/package 不联网的镜像语义）。"""
    monkeypatch.setenv("PKAPP_CACHE", str(tmp_path / "cache"))
    pins, src_map = _pins_for_fetch(tmp_path)
    monkeypatch.setattr(toolchain, "PINS", pins)
    from_dir = tmp_path / "from"
    from_dir.mkdir()
    for fname, src in src_map.items():
        shutil.copyfile(src, from_dir / fname)
    assert toolchain.fetch("windows", from_dir=str(from_dir)) == 0    # 零联网
    assert (tmp_path / "cache" / "android" / "gradle-8.9" / "a.txt").is_file()
    # 部分缺件 → 告警列出，缺的转真网络下载（注入失败下载器验证该路径）
    (from_dir / "b.zip").unlink()
    monkeypatch.setenv("PKAPP_CACHE", str(tmp_path / "cache2"))

    def no_net(url, part):
        raise ToolchainError(f"offline: {url}")

    with pytest.raises(ToolchainError, match="b.zip"):
        toolchain.fetch("windows", from_dir=str(from_dir), fetcher=no_net)


# ---------------------------------------------------------------- 路径推导（真 PINS）
def test_managed_runtime_dir_and_android_paths(tmp_path, monkeypatch):
    monkeypatch.setenv("PKAPP_CACHE", str(tmp_path / "cache"))
    assert toolchain.managed_runtime_dir("windows") == \
        str(tmp_path / "cache" / "runtimes" / "pbs-cpython-3.12.14+20260929")
    assert toolchain.managed_runtime_dir("android") == \
        str(tmp_path / "cache" / "runtimes" / "py-android-3.12.14")
    ap = toolchain.android_paths()
    assert ap["java_home"] == str(tmp_path / "cache" / "android" / "jdk" / "jdk-17.0.20.1+1")
    assert ap["android_home"] == str(tmp_path / "cache" / "android" / "sdk")
    gradle_name = "gradle.bat" if os.name == "nt" else "gradle"
    assert ap["gradle"].endswith(os.path.join("gradle-8.9", "bin", gradle_name))
    assert ap["gradle_home"] == str(tmp_path / "cache" / "android" / "gradle-home")


def test_fetch_android_finishes_licenses(tmp_path, monkeypatch):
    """android 收尾：licenses 落盘 + gradle-home 建目录（不预热）。"""
    monkeypatch.setenv("PKAPP_CACHE", str(tmp_path / "cache"))
    z = tmp_path / "z.zip"
    sha = _mk_zip(str(z), inner="jdk-17.0.20.1+1")
    pins = (Pin(id="jdk17", platform="android", filename="jdk17.zip",
                urls=("https://example.test/jdk17.zip",), sha256=sha, kind="zip",
                dest_parent="android/jdk", inner_rename="jdk-17.0.20.1+1"),)
    monkeypatch.setattr(toolchain, "PINS", pins)
    assert toolchain.fetch("android", fetcher=_fetcher_by_name({"jdk17.zip": str(z)})) == 0
    lic = tmp_path / "cache" / "android" / "sdk" / "licenses" / "android-sdk-license"
    assert lic.read_text(encoding="utf-8").strip() == "24333f8a63b6825ea9c5514f83c2829b004d1fee"
    assert (tmp_path / "cache" / "android" / "gradle-home").is_dir()


# ---------------------------------------------------------------- resolve 集成（托管路径契约）
def test_resolve_managed_snapshot_contract(pkapp_cache, tmp_path):
    """托管路径：snapshot.toml python_version 与 spec 声明一致性（fetch 产物锁）。"""
    from dataclasses import replace

    from pkapp.appspec import AppSpec
    from pkapp.packager.runtime import RuntimeResolveError, resolve
    from pkapp.tools.mockkit import make_mock_runtime

    def spec_of(**kw):
        base = dict(name="x", version="0.1.0", entry="a:b", min_app_version="0.1.0")
        base.update(kw)
        return AppSpec(**base)

    # 未声明 python_version → 提示补声明
    with pytest.raises(RuntimeResolveError, match="python_version"):
        resolve(spec_of(), "windows")
    # 托管快照缺失 → 指向 fetch
    s = spec_of(windows_python_version="3.12.14")
    with pytest.raises(RuntimeResolveError, match="pkapp fetch windows"):
        resolve(s, "windows")
    # 快照在位 + snapshot.toml 一致 → 过（B.t① 断言同链路）
    root = toolchain.managed_runtime_dir("windows")
    make_mock_runtime(root)
    with open(os.path.join(root, "snapshot.toml"), "w", encoding="utf-8") as f:
        f.write('python_version = "3.12.14"\n')
    snap = resolve(s, "windows")
    assert snap.python_version == "3.12.14" and snap.python_dll == "python312.dll"
    # 声明与快照不一致 → 报错提示重跑 fetch 或核对声明
    with open(os.path.join(root, "snapshot.toml"), "w", encoding="utf-8") as f:
        f.write('python_version = "3.11.0"\n')
    with pytest.raises(RuntimeResolveError, match="不一致"):
        resolve(s, "windows")
    # 快照缺 snapshot.toml（手工布置）→ 拒绝
    os.remove(os.path.join(root, "snapshot.toml"))
    with pytest.raises(RuntimeResolveError, match="snapshot.toml"):
        resolve(s, "windows")
    # 逃生门：runtime_dir 显式覆盖（version 仍取声明）
    with open(os.path.join(root, "snapshot.toml"), "w", encoding="utf-8") as f:
        f.write('python_version = "3.11.0"\n')           # 逃生门不读 snapshot
    s2 = replace(s, windows_runtime_dir=root)
    assert resolve(s2, "windows").dir == os.path.abspath(root)
