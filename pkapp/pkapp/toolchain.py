"""工具链托管（pkapp fetch 的实现；pkapp.toml 单一入口 + runtime.lock 退役）。

终态裁定（2026-10-02）：
- **pkapp fetch 是唯一网络入口**——build/package 绝不隐式联网，缺失 fail-fast 并提示 fetch。
- **直链 zip 方案**（非 sdkmanager）：dl.google.com 国内可直连；GitHub 类不稳 →
  PKAPP_MIRROR_* 前缀替换镜像；终极兜底 --from <本地目录> 离线导入。
- **snapshot.toml 从输入变产物**：fetch 写入（id/url/sha256/fetched_at/python_version），
  resolve 据此核对 python_version 一致性（旧 runtime.lock 的输入角色退役）。

sha256 语义："" = 未核定（google 四包，repository2-3.xml 无哈希元数据）——下载仅 TLS
保障 + 打印实测哈希提示回填；非空则 .part 校验不符即删件报错。
"""
from __future__ import annotations

import hashlib
import http.client
import os
import shutil
import tarfile
import time
import urllib.request
import zipfile
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass

try:
    import tomllib
except ModuleNotFoundError:  # Python < 3.11
    import tomli as tomllib

PYTHON_VERSION = "3.12.14"   # PINS 全族锁定的 CPython 版本（snapshot.toml 记录）
_GRADLE_BIN = "gradle.bat" if os.name == "nt" else "gradle"
_DOWNLOAD_WORKERS = 4        # 并发下载线程数（dl.google.com 实测可多路并行）

# 镜像 env：前缀替换（apply_mirror 纯函数语义）
_MIRRORS = {"PKAPP_MIRROR_GITHUB": "https://github.com",
            "PKAPP_MIRROR_GOOGLE": "https://dl.google.com",
            "PKAPP_MIRROR_GRADLE": "https://services.gradle.org"}

# licenses 常量（sdkmanager 体系官方公开 hash，gradle 构建前置）
_ANDROID_LICENSE_HASH = "24333f8a63b6825ea9c5514f83c2829b004d1fee"


class ToolchainError(RuntimeError):
    """工具链缺失 / 下载校验失败 / 解压非法。"""


@dataclass(frozen=True)
class Pin:
    """单一托管组件。filename = dl/ 压缩包名（--from 匹配键，本地名与上游资产名可不同）。"""
    id: str
    platform: str            # windows | android
    filename: str
    urls: tuple              # 主源在前；镜像经 PKAPP_MIRROR_* 前缀替换
    sha256: str              # "" = 未核定（仅 TLS + 打印实测哈希）
    kind: str                # zip | tar.gz | file（裸文件直落，不解压）
    dest_parent: str         # 相对 cache_root 的落盘父目录（/ 分隔）
    inner_rename: str = ""   # 内层目录重命名目标；"" = 保留内层名
    rootless: bool = False   # tar 包根即文件本体（py-android），直接解入 dest_parent


PINS: tuple[Pin, ...] = (
    # ---- windows 运行时（PBS install_only_stripped 精简构建；内层 python/ 名字无关一律重命名）----
    Pin(id="pbs-cpython-3.12.14", platform="windows",
        filename="cpython-3.12.14+20260929-x86_64-pc-windows-msvc-install_only_stripped.tar.gz",
        urls=("https://github.com/astral-sh/python-build-standalone/releases/"
              "download/20260929/cpython-3.12.14+20260929-x86_64-pc-windows-msvc-install_only_stripped.tar.gz",),
        sha256="f38e68f4d612ade6dd50c894fc80b14c0be0c3b5201145d6fff5f20b9323204d",
        kind="tar.gz", dest_parent="runtimes",
        inner_rename="pbs-cpython-3.12.14+20260929"),
    # ---- windows 资源工具（package windows 改图标/版本资源；裸 exe 直落 tools/，不解压）----
    Pin(id="rcedit", platform="windows",
        filename="rcedit-x64.exe",
        urls=("https://github.com/electron/rcedit/releases/download/v2.0.0/rcedit-x64.exe",),
        sha256="3e7801db1a5edbec91b49a24a094aad776cb4515488ea5a4ca2289c400eade2a",
        kind="file", dest_parent="tools"),
    # ---- android 工具链 ----
    Pin(id="jdk17", platform="android",
        filename="jdk17.zip",
        urls=("https://github.com/adoptium/temurin17-binaries/releases/"
              "download/jdk-17.0.20.1%2B1/OpenJDK17U-jdk_x64_windows_hotspot_17.0.20.1_1.zip",),
        sha256="e53a79c3c3d86865bd7e787903884331068e71321714ffd44f145785affc7cb0",
        kind="zip", dest_parent="android/jdk", inner_rename="jdk-17.0.20.1+1"),
    Pin(id="gradle-8.9", platform="android",
        filename="gradle-8.9-bin.zip",
        urls=("https://services.gradle.org/distributions/gradle-8.9-bin.zip",),
        sha256="d725d707bfabd4dfdc958c624003b3c80accc03f7037b5122c4b1d0ef15cecab",
        kind="zip", dest_parent="android", inner_rename="gradle-8.9"),
    # google 四包：repository2-3.xml 无 sha256 元数据 → ""（首下打印实测哈希，人工回填闭环）
    Pin(id="platform-35", platform="android",
        filename="platform-35_r02.zip",
        urls=("https://dl.google.com/android/repository/platform-35_r02.zip",),
        sha256="0988cacad01b38a18a47bac14a0695f246bc76c1b06c0eeb8eb0dc825ab0c8e0",
        kind="zip", dest_parent="android/sdk/platforms", inner_rename="android-35"),
    Pin(id="build-tools-35.0.0", platform="android",
        filename="build-tools_r35_windows.zip",
        urls=("https://dl.google.com/android/repository/build-tools_r35_windows.zip",),
        sha256="5753c679a1b90bcf6fbc9945a2ce39dfb9e74f1df0831a1e1866ae5b594326f0",
        kind="zip", dest_parent="android/sdk/build-tools", inner_rename="35.0.0"),
    Pin(id="platform-tools", platform="android",
        filename="platform-tools_r37.0.1-win.zip",
        urls=("https://dl.google.com/android/repository/platform-tools_r37.0.1-win.zip",),
        sha256="45f4d63113e895ebde0c90f194099a4676b6ac653bd28d54314a9e022bbc1a99",
        kind="zip", dest_parent="android/sdk", inner_rename="platform-tools"),
    Pin(id="cmake-3.22.1", platform="android",
        filename="cmake-3.22.1-windows.zip",
        urls=("https://dl.google.com/android/repository/cmake-3.22.1-windows.zip",),
        sha256="c9a9d568452a20cf27d703cb21ef9529dd67bda6be048c4d4b884acb3ac3a2b8",
        kind="zip", dest_parent="android/sdk/cmake", inner_rename="3.22.1"),
    Pin(id="ndk-27", platform="android",
        filename="android-ndk-r27-windows.zip",
        urls=("https://dl.google.com/android/repository/android-ndk-r27-windows.zip",),
        sha256="342ceafd7581ae26a0bd650a5e0bbcd0aa2ee15eadfd7508b3dedeb1372d7596",
        kind="zip", dest_parent="android/sdk/ndk", inner_rename="27.0.12077973"),
    # ---- android 运行时（flet python-build，rootless tar：条目 ./libpython3.12.so 等）----
    Pin(id="py-android-3.12.14-arm64-v8a", platform="android",
        filename="py-android-arm64.tar.gz",
        urls=("https://github.com/flet-dev/python-build/releases/download/20260921/"
              "python-android-dart-3.12.14-arm64-v8a.tar.gz",),
        sha256="29e4d83f9f7076b42395d70b32b0d951fa514aeb8ac8b4c6381c32bdb4809eb1",
        kind="tar.gz", dest_parent="runtimes/py-android-3.12.14/arm64-v8a", rootless=True),
    Pin(id="py-android-3.12.14-x86_64", platform="android",
        filename="py-android-x86_64.tar.gz",
        urls=("https://github.com/flet-dev/python-build/releases/download/20260921/"
              "python-android-dart-3.12.14-x86_64.tar.gz",),
        sha256="d9ecce41593d7a7b6ef016fe22d143d7732f1ae447bac1f611cf5a7358afde5b",
        kind="tar.gz", dest_parent="runtimes/py-android-3.12.14/x86_64", rootless=True),
)


def _pin(pid: str) -> Pin:
    for p in PINS:
        if p.id == pid:
            return p
    raise ToolchainError(f"未知 pin: {pid}")


def apply_mirror(url: str) -> str:
    """PKAPP_MIRROR_* 前缀替换（纯函数）：命中 origin 前缀则替换为 env 值。"""
    for env, origin in _MIRRORS.items():
        mirror = os.environ.get(env, "")
        if mirror and url.startswith(origin):
            return mirror.rstrip("/") + url[len(origin):]
    return url


def cache_root() -> str:
    """托管缓存根：PKAPP_CACHE > %LOCALAPPDATA%/pkapp（win）> ~/.cache/pkapp。"""
    env = os.environ.get("PKAPP_CACHE")
    if env:
        return env
    if os.name == "nt" and os.environ.get("LOCALAPPDATA"):
        return os.path.join(os.environ["LOCALAPPDATA"], "pkapp")
    return os.path.join(os.path.expanduser("~"), ".cache", "pkapp")


def _split(rel: str) -> list[str]:
    return [seg for seg in rel.split("/") if seg]


def installed_dir(pin: Pin, root: str | None = None) -> str:
    """pin 安装目录（rootless = dest_parent 本体；其余 = dest_parent/<inner_rename>）。

    inner_rename=""（保留内层名）时安装目录名只有解压后才知道——生产 PINS 全部
    显式命名，此形态仅供测试；调用将抛错以防误用（_install 自行计算）。
    """
    base = root or cache_root()
    if pin.rootless:
        return os.path.join(base, *_split(pin.dest_parent))
    if not pin.inner_rename:
        raise ToolchainError(f"pin {pin.id} inner_rename 为空（保留内层名），"
                             "无法预知安装目录")
    return os.path.join(base, *_split(pin.dest_parent), pin.inner_rename)


def managed_runtime_dir(platform: str, root: str | None = None) -> str:
    """平台托管运行时快照根（由 pin 常量推导——mock 测试同源，不脱钩）。

    windows = <cache>/runtimes/pbs-cpython-3.12.14+20260929
    android = <cache>/runtimes/py-android-3.12.14（两 abi 共享父目录）
    """
    for p in PINS:
        if p.platform == platform and _split(p.dest_parent)[0] == "runtimes":
            if p.rootless:   # 两 abi pin 共享父目录
                return os.path.join(root or cache_root(),
                                    *_split(os.path.dirname(p.dest_parent)))
            return installed_dir(p, root)
    raise ToolchainError(f"平台无托管运行时 pin: {platform}")


def rcedit_path(root: str | None = None) -> str:
    """托管 rcedit 裸文件路径（按 pin id 锁定，fetch 未跑时文件不存在）。"""
    for p in PINS:
        if p.id == "rcedit":
            return os.path.join(root or cache_root(), *_split(p.dest_parent), p.filename)
    raise ToolchainError("PINS 无 rcedit pin")


def android_paths(root: str | None = None) -> dict:
    """gradle 构建所需工具链路径（apk.py 解析序：PKAPP_ANDROID_TOOLCHAIN > 此布局）。"""
    base = root or cache_root()
    return {
        "java_home": installed_dir(_pin("jdk17"), base),
        "android_home": os.path.join(base, "android", "sdk"),
        "gradle": os.path.join(installed_dir(_pin("gradle-8.9"), base),
                               "bin", _GRADLE_BIN),
        "gradle_home": os.path.join(base, "android", "gradle-home"),
    }


# ---------------------------------------------------------------- sha256 / 下载
def _sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _urllib_fetch(url: str, part: str, progress: bool = True) -> None:
    """默认下载器（可被注入替换——测试零联网）。并发模式关 progress（多线程 \r 行会交错）。"""
    req = urllib.request.Request(url, headers={"User-Agent": f"pkapp/{_pkapp_version()}"})
    with urllib.request.urlopen(req) as r, open(part, "wb") as f:
        total = int(r.headers.get("Content-Length") or 0)
        done = 0
        while True:
            chunk = r.read(1 << 18)
            if not chunk:
                break
            f.write(chunk)
            done += len(chunk)
            if total and progress:
                print(f"\r  {done >> 20} / {total >> 20} MiB", end="", flush=True)
    if progress:
        print()


def _pkapp_version() -> str:
    from . import __version__
    return __version__


def download(pin: Pin, dl_dir: str, fetcher=None, progress: bool = True) -> str:
    """压缩包就位（幂等）：dl/ 已有且哈希命中跳下载；.part 校验不符删件报错。"""
    final = os.path.join(dl_dir, pin.filename)
    if os.path.isfile(final):
        got = _sha256_file(final)
        if not pin.sha256 or got == pin.sha256:
            return final
        print(f"[fetch] {pin.filename} 缓存哈希不符（重下）")
    part = final + ".part"
    url = apply_mirror(pin.urls[0])
    print(f"[fetch] 下载 {pin.filename}\n        {url}")
    if fetcher is None:
        fetcher = lambda u, p: _urllib_fetch(u, p, progress=progress)   # noqa: E731
    try:
        fetcher(url, part)
    except ToolchainError:
        if os.path.isfile(part):
            os.remove(part)
        raise
    except OSError as e:      # URLError/连接重置等（.part 不留半件）
        if os.path.isfile(part):
            os.remove(part)
        raise ToolchainError(f"下载失败 {url}: {e}") from e
    except http.client.HTTPException as e:   # IncompleteRead 非 OSError 子类，同样不留半件
        if os.path.isfile(part):
            os.remove(part)
        raise ToolchainError(f"下载失败 {url}: {e}") from e
    got = _sha256_file(part)
    if pin.sha256 and got != pin.sha256:
        os.remove(part)
        raise ToolchainError(f"{pin.filename} sha256 校验失败：期望 {pin.sha256}，实得 {got}"
                             "（网络劫持/镜像陈旧？可换 PKAPP_MIRROR_* 或 --from 离线导入）")
    if not pin.sha256:
        print(f"[fetch] 注意：{pin.id} 无基准 sha256（PINS 未核定），实测 = {got}\n"
              f"        请回填 pkapp/toolchain.py PINS 表后重新分发")
    os.replace(part, final)
    return final


def import_from_dir(src_dir: str, dl_dir: str, pins: tuple[Pin, ...]) -> list[str]:
    """--from 离线导入：按 pin.filename 匹配 + sha256 核对（"" 跳过校验）入 dl/。

    不在 PINS 的文件（如 cmdtools.zip）与哈希不符的同名文件一律忽略。
    """
    imported: list[str] = []
    for pin in pins:
        src = os.path.join(src_dir, pin.filename)
        if not os.path.isfile(src):
            continue
        got = _sha256_file(src)
        if pin.sha256 and got != pin.sha256:
            print(f"[fetch] 忽略 {pin.filename}（sha256 不符：期望 {pin.sha256}，实得 {got}）")
            continue
        dest = os.path.join(dl_dir, pin.filename)
        if not os.path.isfile(dest) or _sha256_file(dest) != got:
            shutil.copyfile(src, dest)
        imported.append(pin.id)
    return imported


# ---------------------------------------------------------------- 解压（两态）
def _check_slip(names: list[str], dest: str) -> None:
    """zip-slip 防护：条目归一化路径不得逃出 dest。"""
    base = os.path.abspath(dest)
    for n in names:
        p = os.path.abspath(os.path.join(dest, n.replace("\\", "/")))
        if p != base and not p.startswith(base + os.sep):
            raise ToolchainError(f"压缩包条目越界（zip-slip 防护）: {n!r}")


def _extract(pin: Pin, archive: str, dest: str) -> None:
    os.makedirs(dest, exist_ok=True)
    if pin.kind == "zip":
        with zipfile.ZipFile(archive) as zf:
            _check_slip(zf.namelist(), dest)
            zf.extractall(dest)
    elif pin.kind == "tar.gz":
        with tarfile.open(archive, "r:gz") as tf:
            _check_slip([m.name for m in tf.getmembers()], dest)
            try:
                tf.extractall(dest, filter="data")   # 3.12+：拒绝对外链接/绝对路径
            except TypeError:
                tf.extractall(dest)                  # 旧解释器：靠 _check_slip 兜底
    else:
        raise ToolchainError(f"未知压缩格式: {pin.kind}")


def _find_inner(tmp: str, archive: str) -> str:
    """内层目录定位。两种形态：
    - zip 根恰为单一目录（platform-tools/jdk/ndk…）→ 返回该目录；
    - zip 根多条目（cmake 直链包：bin/doc/share/source.properties）→ tmp 本身
      即组件根（调用方按 inner_rename 命名落位，如 cmake/3.22.1）。"""
    entries = os.listdir(tmp)
    dirs = [e for e in entries if os.path.isdir(os.path.join(tmp, e))]
    if len(entries) == 1 and len(dirs) == 1:
        return os.path.join(tmp, dirs[0])
    if len(entries) > 1:
        return tmp
    raise ToolchainError(f"{os.path.basename(archive)} 解压后无内容: {entries}")


# ---------------------------------------------------------------- snapshot.toml（产物）
def _snap_write(path: str, pin: Pin, sha: str) -> None:
    """合并式写入（[pins.<id>] 分节，多 pin 共享一份 snapshot 时互不覆盖）。"""
    table: dict = {}
    if os.path.isfile(path):
        with open(path, "rb") as f:
            try:
                table = tomllib.load(f)
            except tomllib.TOMLDecodeError:
                table = {}   # 损坏快照按缺失重建
    table["python_version"] = PYTHON_VERSION
    pins = table.setdefault("pins", {})
    pins[pin.id] = {"url": pin.urls[0], "sha256": sha,
                    "fetched_at": time.strftime("%Y-%m-%d %H:%M:%S"),
                    "python_version": PYTHON_VERSION}
    lines = [f'python_version = "{PYTHON_VERSION}"', ""]
    for pid, kv in pins.items():
        # pin id 含 "."（版本号）——裸键会被解析成嵌套表，必须引号化
        lines.append(f'[pins."{pid}"]')
        for k, v in kv.items():
            lines.append(f'{k} = "{v}"')
        lines.append("")
    tmp = path + f".tmp{os.getpid()}"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    os.replace(tmp, path)


def _snap_has(path: str, pin: Pin, sha: str) -> bool:
    if not os.path.isfile(path):
        return False
    with open(path, "rb") as f:
        try:
            data = tomllib.load(f)
        except tomllib.TOMLDecodeError:
            return False
    entry = (data.get("pins") or {}).get(pin.id) or {}
    return entry.get("sha256") == sha


# ---------------------------------------------------------------- fetch 主流程
def fetch(platform: str, from_dir: str | None = None, list_only: bool = False,
          fetcher=None, root: str | None = None) -> int:
    """唯一网络入口：取压缩包 → 解压安装 → 写 snapshot.toml（lock 从输入变产物）。"""
    pins = tuple(p for p in PINS if p.platform == platform)
    if not pins:
        raise ToolchainError(f"未知平台: {platform}（目标仅 windows/android）")
    if list_only:
        for p in pins:
            mark = "已核定" if p.sha256 else "未核定"
            print(f"{p.id:32} {p.filename:55} [{mark}]")
        return 0

    base = root or cache_root()
    dl_dir = os.path.join(base, "dl")
    os.makedirs(dl_dir, exist_ok=True)

    if from_dir:
        imported = import_from_dir(from_dir, dl_dir, pins)
        print(f"[fetch] --from 离线导入: {', '.join(imported) or '（无命中）'}")
        missing = [p.filename for p in pins
                   if not os.path.isfile(os.path.join(dl_dir, p.filename))]
        if missing:
            print("[fetch] 警告: --from 目录缺以下压缩包，对应组件稍后转真网络下载"
                  "（离线机请补齐后重跑）：\n  " + "\n  ".join(missing))

    _download_all(pins, dl_dir, fetcher)
    for p in pins:
        _install(p, dl_dir, base)
    if platform == "android":
        _finish_android(base)
    print(f"[fetch] {platform} 工具链就绪 @ {base}")
    return 0


def _download_all(pins: tuple[Pin, ...] | list[Pin], dl_dir: str, fetcher) -> None:
    """并发下载（下载是 IO 密集——ThreadPoolExecutor 足够，无需 asyncio）。

    预检缺件/缓存哈希不符者进池；单件走串行（保留 per-MiB 进度行）；
    任一失败等全部收尾后汇总报错（download 幂等，重跑自动续）。
    """
    missing = []
    for p in pins:
        final = os.path.join(dl_dir, p.filename)
        if os.path.isfile(final):
            if not p.sha256 or _sha256_file(final) == p.sha256:
                continue          # 命中（未核定 + 文件在 = 命中，与 download 语义一致）
        missing.append(p)
    if not missing:
        return
    if len(missing) == 1:
        download(missing[0], dl_dir, fetcher)
        return
    workers = min(_DOWNLOAD_WORKERS, len(missing))
    print(f"[fetch] 并发下载 {len(missing)} 个组件（{workers} 线程）…")
    failures: list[str] = []

    def work(pin: Pin) -> None:
        t0 = time.time()
        try:
            download(pin, dl_dir, fetcher, progress=False)
            size = os.path.getsize(os.path.join(dl_dir, pin.filename)) >> 20
            print(f"[fetch]   ✓ {pin.filename}（{size} MiB / {time.time() - t0:.1f}s）")
        except ToolchainError as e:
            failures.append(f"{pin.filename}: {e}")

    with ThreadPoolExecutor(max_workers=workers) as ex:
        list(ex.map(work, missing))
    if failures:
        raise ToolchainError(f"下载失败（{len(failures)} 个）：\n  "
                             + "\n  ".join(failures))


def _install(pin: Pin, dl_dir: str, base: str) -> None:
    archive = os.path.join(dl_dir, pin.filename)
    sha = pin.sha256 or _sha256_file(archive)
    if pin.kind == "file":
        # 裸文件（rcedit 等单 exe 工具）：dl/ 直拷落位，无解压无内层概念
        dest = os.path.join(base, *_split(pin.dest_parent), pin.filename)
        snap = os.path.join(os.path.dirname(dest), "snapshot.toml")
        if os.path.isfile(dest) and _snap_has(snap, pin, sha):
            print(f"[fetch] {pin.id} 已就位（跳过）")
            return
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        shutil.copyfile(archive, dest)
        _snap_write(snap, pin, sha)
        print(f"[fetch] {pin.id} → {dest}")
        return
    if pin.rootless:
        # tar 包根即文件本体（./libpython3.12.so …）——直接解入 <dest_parent>，
        # snapshot.toml 写共享父目录（py-android 两 abi 同源）
        dest = installed_dir(pin, base)
        snap = os.path.join(os.path.dirname(dest), "snapshot.toml")
        if os.path.isdir(dest) and _snap_has(snap, pin, sha):
            print(f"[fetch] {pin.id} 已就位（跳过）")
            return
        if os.path.isdir(dest):
            shutil.rmtree(dest)      # 重装（snapshot 缺条目/损坏）先清旧目录，防陈旧残留
        _extract(pin, archive, dest)
        _snap_write(snap, pin, sha)
        print(f"[fetch] {pin.id} → {dest}")
        return
    # 单一内层目录形态：解压到同卷 tmp → os.replace 到位（inner_rename="" = 保留内层名）
    tmp = os.path.join(base, *_split(pin.dest_parent), f".tmp{pin.id.replace('.', '_')}{os.getpid()}")
    shutil.rmtree(tmp, ignore_errors=True)
    try:
        _extract(pin, archive, tmp)
        inner = _find_inner(tmp, archive)
        if inner == tmp and not pin.inner_rename:
            raise ToolchainError(
                f"{os.path.basename(archive)} 根级多条目（无内层目录），必须指定 inner_rename")
        name = pin.inner_rename or os.path.basename(inner)
        dest = os.path.join(base, *_split(pin.dest_parent), name)
        snap = os.path.join(dest, "snapshot.toml")
        if os.path.isdir(dest) and _snap_has(snap, pin, sha):
            print(f"[fetch] {pin.id} 已就位（跳过）")
            return
        if os.path.isdir(dest):
            shutil.rmtree(dest)      # 陈旧重装（托管目录，可安全重建）
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        _replace_with_retry(inner, dest)
        _snap_write(snap, pin, sha)
        print(f"[fetch] {pin.id} → {dest}")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def _replace_with_retry(src: str, dest: str, timeout: float = 60.0) -> None:
    """os.replace 目录到位，带瞬态句柄锁重试。

    Windows 上新解压目录可能被 Defender/索引服务短暂持有句柄，rename 即报
    WinError 5（实测 gradle 首装复现：空闲时秒过，与其他解压/下载并行的杀软
    重载期锁窗可达数十秒）——退避重试至多 60s 并打印进度；超时才放弃。
    """
    deadline = time.monotonic() + timeout
    delay = 0.5
    while True:
        try:
            os.replace(src, dest)
            return
        except PermissionError as e:
            if time.monotonic() >= deadline:
                raise ToolchainError(
                    f"安装失败（目录被占用超过 {timeout:.0f}s——关闭占用程序后重跑 pkapp fetch）: {e}"
                ) from e
            print(f"[fetch] {os.path.basename(src)} 目录暂被占用（杀软扫描？），"
                  f"{max(1, round(delay))}s 后重试…")
            time.sleep(delay)
            delay = min(delay * 1.5, 8.0)


def _finish_android(base: str) -> None:
    """licenses + gradle-home（只建目录不预热——首次 gradle 构建仍需联网拉 AGP 依赖）。"""
    lic_dir = os.path.join(base, "android", "sdk", "licenses")
    os.makedirs(lic_dir, exist_ok=True)
    lic = os.path.join(lic_dir, "android-sdk-license")
    if not os.path.isfile(lic):
        with open(lic, "w", encoding="utf-8") as f:
            f.write(_ANDROID_LICENSE_HASH + "\n")
    os.makedirs(os.path.join(base, "android", "gradle-home"), exist_ok=True)
