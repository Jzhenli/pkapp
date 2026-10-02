"""运行时快照解析器（方案 §一 RT；runtime.lock 退役后 = pkapp.toml 声明意图 + 托管快照）。

解析序（2026-10-02 裁定）：
1. [platforms.*].runtime_dir 显式覆盖（逃生门；version 仍取对应 spec.python_version）
2. toolchain 托管缓存 `pkapp fetch <platform>` 产物（managed_runtime_dir）
3. 全部落空 → RuntimeResolveError，文案指向 fetch 命令

托管路径下核对 <dir>/snapshot.toml 的 python_version 与 spec 声明一致（fetch 写入的
产物锁——"lock 从输入变产物"）；spec 未声明 python_version → 报错提示补声明。

B.t① 断言保留：目录必须含 python3XX.dll（共享构建，Py_ENABLE_SHARED）——
静态 libpython 时 getpath 的 library 为空，_pth 退回按 EXE 目录查找（V4）。
"""
from __future__ import annotations

import glob
import os
import re
from dataclasses import dataclass

from .. import toolchain

try:
    import tomllib
except ModuleNotFoundError:  # Python < 3.11
    import tomli as tomllib


class RuntimeResolveError(ValueError):
    """运行时快照缺失 / 指向无效 / 与 spec 声明不一致（fail fast，不得留到壳侧）。"""


@dataclass(frozen=True)
class RuntimeSnapshot:
    platform: str          # windows | linux | android
    dir: str               # 快照根目录（含解释器本体的"安装目录"形态）
    python_version: str
    python_dll: str        # 解释器本体文件名（如 python312.dll）；B.x/_pth 由此派生
    abis: tuple = ()       # android：快照覆盖的 ABI 列表（dir 下按 <abi>/ 子目录布局）


def _declared(spec, platform: str) -> tuple[str, str]:
    """(python_version, runtime_dir 覆盖) —— 取自 pkapp.toml 对应平台段。"""
    if platform == "windows":
        return spec.windows_python_version, spec.windows_runtime_dir
    if platform == "android":
        return spec.android_python_version, spec.android_runtime_dir
    raise RuntimeResolveError(f"{platform} 目标在 M3 接入（当前支持 windows/android）")


def _snapshot_version(root: str) -> str:
    path = os.path.join(root, "snapshot.toml")
    try:
        with open(path, "rb") as f:
            return str((tomllib.load(f) or {}).get("python_version", ""))
    except FileNotFoundError:
        return ""
    except tomllib.TOMLDecodeError as e:
        raise RuntimeResolveError(f"{path} 不是合法 TOML: {e}") from e


def resolve(spec, platform: str, abis: tuple = ("arm64-v8a",)) -> RuntimeSnapshot:
    """解析 + 校验平台快照。任何缺失/非法 → RuntimeResolveError（fail fast）。"""
    declared, override = _declared(spec, platform)
    if not declared:
        seg = "windows" if platform == "windows" else "android"
        raise RuntimeResolveError(
            f"pkapp.toml 缺 [platforms.{seg}].python_version——声明运行时意图"
            f"（如 python_version = \"{toolchain.PYTHON_VERSION}\"），"
            f"然后运行 pkapp fetch {platform}")

    if override:
        root = override
        if not os.path.isdir(root):
            raise RuntimeResolveError(
                f"[platforms.{platform}].runtime_dir 不存在或未指向目录: {root!r}")
        version = declared
    else:
        try:
            root = toolchain.managed_runtime_dir(platform)
        except toolchain.ToolchainError as e:
            raise RuntimeResolveError(str(e)) from e
        if not os.path.isdir(root):
            raise RuntimeResolveError(
                f"托管运行时快照缺失: {root}——运行 `pkapp fetch {platform}`"
                f"（build/package 不隐式联网）")
        version = _snapshot_version(root)
        if not version:
            raise RuntimeResolveError(
                f"{root} 缺 snapshot.toml 或未记录 python_version——重跑 "
                f"`pkapp fetch {platform}`（须由 fetch 产出，勿手工布置）")
        if version != declared:
            seg = "windows" if platform == "windows" else "android"
            raise RuntimeResolveError(
                f"快照 python_version ({version}) 与 [platforms.{seg}].python_version "
                f"({declared}) 不一致——重跑 `pkapp fetch {platform}` 或核对声明")

    if platform == "windows":
        dll = _detect_windows_dll(root)
        for sub in ("Lib", "DLLs"):
            if not os.path.isdir(os.path.join(root, sub)):
                raise RuntimeResolveError(f"快照缺 {sub}/ 目录: {root}（PBS 安装目录形态）")
    elif platform == "android":
        if not abis:
            raise RuntimeResolveError("abis 为空（AppSpec [platforms.android].abis）")
        dll = ""
        for abi in abis:
            hit = _detect_android_dir(root, abi)
            dll = dll or hit  # python_dll 名三 ABI 一致，取首个
    else:
        dll = _detect_linux_so(root)
    return RuntimeSnapshot(platform=platform, dir=os.path.abspath(root),
                           python_version=version, python_dll=dll,
                           abis=tuple(abis) if platform == "android" else ())


def _detect_windows_dll(root: str) -> str:
    """B.t①：共享构建断言——根目录必须存在 python3NN.dll（版本号数字必现）。

    正则排除 python3.dll（稳定 ABI 转发器，非解释器本体）——实测教训：
    字典序下 python3.dll < python312.dll，宽松 glob 会选错（M0 D2 回填）。
    """
    hits = sorted(f for f in os.listdir(root)
                  if re.match(r"^python3\d+\.dll$", f, re.IGNORECASE))
    if not hits:
        raise RuntimeResolveError(
            f"{root} 下未找到 python3NN.dll：不是含解释器 DLL 的共享构建（B.t①，Py_ENABLE_SHARED）")
    return hits[0]


def _detect_linux_so(root: str) -> str:
    hits = sorted(glob.glob(os.path.join(root, "libpython3*.so*")))
    if not hits:
        raise RuntimeResolveError(f"{root} 下未找到 libpython3*.so*（Linux 快照布局）")
    return os.path.basename(hits[0])


def _detect_android_dir(root: str, abi: str) -> str:
    """Android 快照 = flet python-build 产物：<dir>/<abi>/{libpython3NN.so, libpythonbundle.so}。

    libpythonbundle.so 是 zip（stdlib/ + modules/ 扩展模块）——spk 的 runtime_hash
    取其 sha256，标识应用构建所针对的运行时 bundle。
    """
    d = os.path.join(root, abi)
    if not os.path.isdir(d):
        raise RuntimeResolveError(f"运行时快照缺 <abi> 子目录: {d}（布局 <dir>/<abi>/）")
    hits = sorted(f for f in os.listdir(d) if re.match(r"^libpython3\.\d+\.so$", f))
    if not hits:
        raise RuntimeResolveError(f"{d} 下未找到 libpython3NN.so（flet android 快照布局）")
    if not os.path.isfile(os.path.join(d, "libpythonbundle.so")):
        raise RuntimeResolveError(f"{d} 缺 libpythonbundle.so（stdlib+扩展模块 bundle）")
    return hits[0]


def dll_stem(python_dll: str) -> str:
    """python312.dll → python312（_pth/stdlib zip 命名派生，B.x）。"""
    return os.path.splitext(python_dll)[0]
