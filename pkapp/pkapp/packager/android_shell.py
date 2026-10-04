"""Android 壳模板物化 + 运行时注入（★方案A★，借鉴 Briefcase：模板+构建期注入+持久生成工程）。

分工（canonical 逻辑只此一处，shell/tools/prepare_runtime.py 已退役）：
- 模板源 = --shell-dir / PKAPP_SHELL_DIR（语义=壳模板根）/ 仓库 shell-android/shell /
  wheel 内置 _vendor/shell-android——裸模板不含 jniLibs/stdlib.zip/二进制（~150KB 源码）。
- 指纹   = sha256(pkapp版本 + 模板全部文件 + 各abi libpython3.12.so/libpythonbundle.so + abis)。
- 物化   = 全新拷贝到 <cache>/shells/android/android-<fp12>/；命中指纹即复用（gradle
  增量），指纹变（pkapp 升级/换 python/换 abi/改模板）才冷构建一次；仅保留最近 2 个。
- 注入   = 托管快照 <runtime>/<abi>/：顶层 .so（除 bundle）原样 copy + bundle 内
  modules/X → jniLibs/lib+X（★lib 前缀契约★：release 安装器只抽 lib*.so，applocal
  NdkExtFinder 消费 lib+原名，见 applocal/_ndk.py）+ stdlib/* → assets/stdlib.zip
  （ZIP_STORED——android libpython 无 zlib，DEFLATE 在 init_fs_encoding 炸，D1 硬约束；
ABI 公共，仅生成一次）。
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import zipfile

_BUNDLE = "libpythonbundle.so"
_MARKER = ".pkapp-shell.json"
_KEEP_DIRS = 2          # 物化目录淘汰水位（保留最近 N 个指纹）
_IGNORE = shutil.ignore_patterns("build", ".gradle", ".cxx", ".kotlin", "__pycache__", "*.pyc")


class AndroidShellError(RuntimeError):
    """壳模板物化/注入失败（模板缺失 / 运行时快照缺失 / abi 目录不完整）。"""


def vendored_template_dir() -> str | None:
    """wheel 内置壳模板（scripts/vendor.py 组装；源码仓库形态可能无 _vendor）。"""
    p = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                     "_vendor", "shell-android")
    return p if os.path.isfile(os.path.join(p, "settings.gradle.kts")) else None


def _sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


# ---------------------------------------------------------------- 指纹
def fingerprint(template_root: str, runtime_dir: str | None,
                abis: tuple[str, ...]) -> str:
    """壳工程身份：模板内容 × 运行时内容 × abi 集 × pkapp 版本（任一变 → 新目录冷构建）。"""
    from .. import __version__

    h = hashlib.sha256()
    h.update(f"pkapp={__version__}\n".encode())
    h.update(f"abis={','.join(abis)}\n".encode())
    for root, dirs, files in os.walk(template_root):
        dirs[:] = [d for d in dirs if d not in ("build", ".gradle", ".cxx",
                                                ".kotlin", "__pycache__")]
        for name in sorted(files):
            p = os.path.join(root, name)
            rel = os.path.relpath(p, template_root).replace("\\", "/")
            h.update(f"{rel}:{_sha256_file(p)}\n".encode())
    if runtime_dir:
        for abi in abis:
            for name in (_BUNDLE, "libpython3.12.so"):
                p = os.path.join(runtime_dir, abi, name)
                h.update(f"{abi}/{name}:{_sha256_file(p)}\n".encode())
    return h.hexdigest()


# ---------------------------------------------------------------- 物化
def materialize(template_root: str, runtime_dir: str | None,
                abis: tuple[str, ...]) -> str:
    """模板 → <cache>/shells/android/android-<fp12>/（复用或全新拷贝）→ 注入运行时。

    返回可构建的壳工程根（apk.py 对其拷 spk → gradle）；任何失败抛 AndroidShellError。
    """
    from .. import toolchain

    if not abis:
        raise AndroidShellError("abis 为空（AppSpec [platforms.android].abis）——注入无目标 abi")
    if not runtime_dir or not os.path.isdir(runtime_dir):
        raise AndroidShellError("壳模板为裸模板（无 jniLibs）但 android 运行时快照不可用"
                                "——先 `pkapp fetch android`")
    # fail-fast 前置：fingerprint 逐文件哈希各 abi 快照，缺席会炸 FileNotFoundError——
    # 先行校验给 AndroidShellError 语义（缺席目录/不完整快照都指向 fetch）
    for abi in abis:
        src = os.path.join(runtime_dir, abi)
        if not os.path.isdir(src):
            raise AndroidShellError(f"运行时快照缺 {abi}/ 目录: {runtime_dir}——重跑 "
                                    "`pkapp fetch android` 或核对 [platforms.android].abis")
        for name in ("libpython3.12.so", _BUNDLE):
            if not os.path.isfile(os.path.join(src, name)):
                raise AndroidShellError(f"运行时快照 {abi}/ 缺 {name}（不完整）——重跑 "
                                        "`pkapp fetch android`（勿手工布置快照）")
    fp = fingerprint(template_root, runtime_dir, abis)
    work_root = os.path.join(toolchain.cache_root(), "shells", "android")
    work = os.path.join(work_root, f"android-{fp[:12]}")
    marker = os.path.join(work, _MARKER)
    try:
        hit = (os.path.isfile(marker)
               and json.load(open(marker, encoding="utf-8")).get("fingerprint") == fp)
    except (OSError, ValueError):   # marker 半截（上次构建中断残留）→ 缓存 miss 重建
        hit = False
    if not hit:
        shutil.rmtree(work, ignore_errors=True)
        os.makedirs(work_root, exist_ok=True)
        shutil.copytree(template_root, work, ignore=_IGNORE)
        _inject(work, runtime_dir, abis)
        with open(marker, "w", encoding="utf-8") as f:
            json.dump({"fingerprint": fp, "abis": list(abis),
                       "template": os.path.abspath(template_root)}, f, ensure_ascii=False)
        # copytree 的 copystat 让物化目录继承模板 mtime——同模板多指纹目录 mtime 全同
        # 会使 _prune"保留最近"失真；刷新为物化时刻恢复语义
        os.utime(work, None)
        _prune(work_root, work)
    return work


def _prune(work_root: str, keep: str) -> None:
    """淘汰旧指纹目录（保留当前 + 最近 _KEEP_DIRS-1 个，按物化时刻 mtime）。"""
    try:
        dirs = [os.path.join(work_root, d) for d in os.listdir(work_root)
                if d.startswith("android-") and os.path.isdir(os.path.join(work_root, d))]
    except OSError:
        return
    for d in sorted(dirs, key=os.path.getmtime, reverse=True)[_KEEP_DIRS:]:
        if os.path.abspath(d) != os.path.abspath(keep):
            shutil.rmtree(d, ignore_errors=True)


# ---------------------------------------------------------------- 注入
def _copy_if_changed(src: str, dst: str) -> None:
    if os.path.isfile(dst) and os.path.getsize(dst) == os.path.getsize(src):
        return
    shutil.copyfile(src, dst)


def _inject(work: str, runtime_dir: str, abis: tuple[str, ...]) -> None:
    """托管快照 → 壳工程（幂等：同尺寸跳过）。契约见模块 docstring。"""
    assets = os.path.join(work, "app", "src", "main", "assets")
    jni_root = os.path.join(work, "app", "src", "main", "jniLibs")
    stdlib_done = False
    for abi in abis:
        src = os.path.join(runtime_dir, abi)
        if not os.path.isdir(src):
            raise AndroidShellError(f"运行时快照缺 {abi}/ 目录: {runtime_dir}——重跑 "
                                    "`pkapp fetch android` 或核对 [platforms.android].abis")
        jni = os.path.join(jni_root, abi)
        os.makedirs(jni, exist_ok=True)
        # 1) 顶层支撑件 + libpython 本体（bundle 除外：其内容拆铺 jniLibs 与 assets）
        for name in sorted(os.listdir(src)):
            p = os.path.join(src, name)
            if name != _BUNDLE and os.path.isfile(p):
                _copy_if_changed(p, os.path.join(jni, name))
        # 2) bundle：modules/X → jniLibs/lib+X；stdlib/* → assets/stdlib.zip（ABI 公共一次）
        bundle = os.path.join(src, _BUNDLE)
        if not os.path.isfile(bundle):
            raise AndroidShellError(f"{bundle} 缺失（stdlib+扩展模块 bundle）——重跑 "
                                    "`pkapp fetch android`（勿手工布置快照）")
        with zipfile.ZipFile(bundle) as zf:
            infos = [i for i in zf.infolist() if not i.is_dir()]
            for info in infos:
                if info.filename.startswith("modules/"):
                    dst = os.path.join(jni, "lib" + os.path.basename(info.filename))
                    if not (os.path.isfile(dst) and os.path.getsize(dst) == info.file_size):
                        with open(dst, "wb") as f:
                            f.write(zf.read(info))
                elif info.filename.startswith("stdlib/") and not stdlib_done:
                    os.makedirs(assets, exist_ok=True)
                    out = os.path.join(assets, "stdlib.zip")
                    if not os.path.isfile(out):
                        with zipfile.ZipFile(out, "w", zipfile.ZIP_STORED) as o:
                            for si in infos:
                                if si.filename.startswith("stdlib/"):
                                    o.writestr(si.filename.removeprefix("stdlib/"),
                                               zf.read(si))
                    stdlib_done = True
        # 3) 硬门禁：CMake IMPORTED_LOCATION 与 waitForNativeLibs 都认 libpython3.12.so
        if not os.path.isfile(os.path.join(jni, "libpython3.12.so")):
            raise AndroidShellError(f"注入后 jniLibs/{abi}/ 缺 libpython3.12.so"
                                    f"（快照 {src} 不完整？）")
    if stdlib_done:
        os.utime(assets, None)   # 增量 mergeDebugAssets mtime 盲区（apk.py 拷 spk 后再 touch，双保险）
