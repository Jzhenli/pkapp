"""运行时快照解析器（方案 §一 RT：CPython 来源 = python-build 产物，快照锁定，manifest 驱动）。

runtime.lock（项目根，TOML）：
    [runtime.windows]
    python_version = "3.12.14"
    dir = "D:/runtimes/pbs-cpython-3.12.14"     # 解压后的安装目录

B.t① 断言：目录必须含 python3XX.dll（共享构建，Py_ENABLE_SHARED）——
静态 libpython 时 getpath 的 library 为空，_pth 退回按 EXE 目录查找（V4）。
Mock 先行：tests 生成同构假 runtime 驱动 golden test；真 PBS 接入后同一管线复验。
"""
from __future__ import annotations

import glob
import os
from dataclasses import dataclass

try:
    import tomllib
except ModuleNotFoundError:  # Python < 3.11
    import tomli as tomllib


class RuntimeLockError(ValueError):
    """runtime.lock 缺失 / 指向无效快照。"""


@dataclass(frozen=True)
class RuntimeSnapshot:
    platform: str          # windows | linux | android
    dir: str               # 快照根目录（含解释器本体的"安装目录"形态）
    python_version: str
    python_dll: str        # 解释器本体文件名（如 python312.dll）；B.x/_pth 由此派生
    abis: tuple = ()       # android：快照覆盖的 ABI 列表（dir 下按 <abi>/ 子目录布局）


def load_lock(project_dir: str) -> dict:
    path = os.path.join(project_dir, "runtime.lock")
    try:
        with open(path, "rb") as f:
            return tomllib.load(f)
    except FileNotFoundError as e:
        raise RuntimeLockError(
            f"未找到 {path}——build 前须注册运行时快照（见 runtime.lock 模板）") from e
    except tomllib.TOMLDecodeError as e:
        raise RuntimeLockError(f"{path} 不是合法 TOML: {e}") from e


def _detect_windows_dll(root: str) -> str:
    """B.t①：共享构建断言——根目录必须存在 python3NN.dll（版本号数字必现）。

    正则排除 python3.dll（稳定 ABI 转发器，非解释器本体）——实测教训：
    字典序下 python3.dll < python312.dll，宽松 glob 会选错（M0 D2 回填）。
    """
    import re
    hits = sorted(f for f in os.listdir(root)
                  if re.match(r"^python3\d+\.dll$", f, re.IGNORECASE))
    if not hits:
        raise RuntimeLockError(
            f"{root} 下未找到 python3NN.dll：不是含解释器 DLL 的共享构建（B.t①，Py_ENABLE_SHARED）")
    return hits[0]


def _detect_linux_so(root: str) -> str:
    hits = sorted(glob.glob(os.path.join(root, "libpython3*.so*")))
    if not hits:
        raise RuntimeLockError(f"{root} 下未找到 libpython3*.so*（Linux 快照布局）")
    return os.path.basename(hits[0])


def _detect_android_dir(root: str, abi: str) -> str:
    """Android 快照 = flet python-build 产物：<dir>/<abi>/{libpython3NN.so, libpythonbundle.so}。

    libpythonbundle.so 是 zip（stdlib/ + modules/ 扩展模块）——spk 的 runtime_hash
    取其 sha256，标识应用构建所针对的运行时 bundle。
    """
    import re
    d = os.path.join(root, abi)
    if not os.path.isdir(d):
        raise RuntimeLockError(f"[runtime.android] 缺 <abi> 子目录: {d}（布局 <dir>/<abi>/）")
    hits = sorted(f for f in os.listdir(d) if re.match(r"^libpython3\.\d+\.so$", f))
    if not hits:
        raise RuntimeLockError(f"{d} 下未找到 libpython3NN.so（flet android 快照布局）")
    if not os.path.isfile(os.path.join(d, "libpythonbundle.so")):
        raise RuntimeLockError(f"{d} 缺 libpythonbundle.so（stdlib+扩展模块 bundle）")
    return hits[0]


def resolve(project_dir: str, platform: str, abis: tuple = ("arm64-v8a",)) -> RuntimeSnapshot:
    """解析 + 校验平台快照。任何缺失/非法 → RuntimeLockError（fail fast，不得留到壳侧）。"""
    table = load_lock(project_dir).get("runtime") or {}
    entry = table.get(platform)
    if not entry:
        raise RuntimeLockError(f"runtime.lock 缺少 [runtime.{platform}] 段")
    root = str(entry.get("dir", ""))
    if not root or not os.path.isdir(root):
        raise RuntimeLockError(f"[runtime.{platform}].dir 不存在或未指向目录: {root!r}")
    version = str(entry.get("python_version", ""))
    if not version:
        raise RuntimeLockError(f"[runtime.{platform}].python_version 必填（快照锁定语义）")
    if platform == "windows":
        dll = _detect_windows_dll(root)
        for sub in ("Lib", "DLLs"):
            if not os.path.isdir(os.path.join(root, sub)):
                raise RuntimeLockError(f"快照缺 {sub}/ 目录: {root}（PBS 安装目录形态）")
    elif platform == "android":
        if not abis:
            raise RuntimeLockError("[runtime.android] abis 为空（AppSpec [platforms.android].abis）")
        dll = ""
        for abi in abis:
            hit = _detect_android_dir(root, abi)
            dll = dll or hit  # python_dll 名三 ABI 一致，取首个
    else:
        dll = _detect_linux_so(root)
    return RuntimeSnapshot(platform=platform, dir=os.path.abspath(root),
                           python_version=version, python_dll=dll,
                           abis=tuple(abis) if platform == "android" else ())


def dll_stem(python_dll: str) -> str:
    """B.x：python_dll 去扩展名 → python312（zip / _pth 文件名派生自它，V13）。"""
    base = os.path.basename(python_dll)
    for ext in (".dll",):
        if base.lower().endswith(ext):
            return base[:-len(ext)]
    # POSIX：libpython3.12.so.1.0 → 取首段
    return base.split(".so")[0].removeprefix("lib")
