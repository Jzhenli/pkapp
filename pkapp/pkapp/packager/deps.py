"""wheel 托管缓存 + pip 安装面（拆分前居于 assemble）。

- 缓存路径与需求匹配（PEP 503/440 轻量等价）：_wheels_cache/_dep_name/_wheel_name/
  _dep_version/_ver_hit/_uncached_deps；
- pip --target 装入（离线供应商目录 / 托管缓存在线补齐两态）：_install_site_packages；
- android 交叉安装标签集：_android_pip_tags；
- applocal dist 版本探测：_detect_applocal。
"""
from __future__ import annotations

import glob
import importlib.metadata
import os
import re
import subprocess
import sys

from ..appspec import AppSpec
from ..toolchain import cache_root
from .errors import BuildError


def _wheels_cache(platform: str, abi: str | None = None) -> str:
    """★v1.4★ wheel 托管缓存全局化：<PKAPP_CACHE|默认托管根>/wheels/<platform>——
    与工具链同源（toolchain.cache_root），跨项目复用免重复下载；platform 子目录
    隔离标签集（windows 与 android 交叉 wheel 混判会让离线优先误命中）。android
    再按 <abi> 分层（★实测教训★：双 ABI 共缓存时，v7a 先建会把 arm32 的
    pydantic_core 写进缓存，arm64 构建"顶层需求已缓存"短路后死路——abi 目录
    隔离与"单 ABI 构建"约束对齐）。★R-L17★ linux 同构：第二参传 arch
    （x86_64/aarch64/armv7l，LinuxSpec.abis 元素——交叉 wheel 标签集随 arch
    隔离，同 android 教训）。平台内多版本 wheel 共存无害（pip 按需求挑）；
    显式 --wheels-dir 仍为纯离线供应商目录语义。"""
    if abi:
        return os.path.join(cache_root(), "wheels", platform, abi)
    return os.path.join(cache_root(), "wheels", platform)


def _dep_name(req: str) -> str:
    """PEP 503 归一化需求名（applocal>=0.1.0 → applocal；Foo_bar → foo-bar）。"""
    return re.sub(r"[-_.]+", "-", re.split(r"[!<>=~;\[\s]", req.strip(), 1)[0]).lower()


def _wheel_name(fn: str) -> str:
    """wheel 文件名 → 归一化发行版名（Foo_bar-1.0-*.whl → foo-bar）。"""
    return re.sub(r"[-_.]+", "-", fn.split("-", 1)[0]).lower()


def _dep_version(req: str) -> str:
    """需求内联精确版本 pin（applocal==0.1.0 → 0.1.0；extras 语法 foo[x]==1.0 同样
    识别）；范围（>=/~=/!=）或无 pin 一律返回 ""（文件名无法可靠表达版本区间，
    退化为按名字判缓存）。"""
    m = re.match(r"[^=!<>~;[\s]*(?:\[[^\]]*\])?==\s*([^;,\s]+)", req.strip())
    return m.group(1) if m else ""


def _ver_hit(pin: str, cached: set[str]) -> bool:
    """pin 版本是否命中缓存 wheel 版本集（PEP 440 轻量等价，仅文件名比对用）：
    大小写/前导 v/分隔符归一；纯数字段版本补零对齐（1.0 == 1.0.0）；含非数字段
    （预发布/本地段）退化为严格串等；通配 .* 走归一化前缀匹配。"""
    def norm(v: str) -> str:
        return v.strip().lower().lstrip("v").replace("-", ".").replace("_", ".")

    if pin.endswith(".*"):
        pre = norm(pin[:-2])
        return any(k == pre or k.startswith(pre + ".") for k in map(norm, cached))
    p = norm(pin)
    for k in map(norm, cached):
        sp, sk = p.split("."), k.split(".")
        if all(x.isdigit() for x in sp + sk):
            n = max(len(sp), len(sk))
            if ([int(x) for x in sp + ["0"] * (n - len(sp))]
                    == [int(x) for x in sk + ["0"] * (n - len(sk))]):
                return True
        elif sp == sk:
            return True
    return False


def _uncached_deps(dep_list: list[str], wheels_dir: str) -> list[str]:
    """download 需求过滤：缓存已有发行版不进补齐（applocal 等私有件不在任何公共
    索引——留在列表里只会让 download 炸掉；先入缓存是它们的唯一入口）。
    ★v1.4★ 全局共享缓存后升级为"名字+精确版本"匹配：fastapi==0.115.0 须命中
    fastapi-0.115.0-*.whl 才算已缓存（他项目缓存的 0.110.0 不得误判，否则
    --no-index 离线安装必炸且无补齐机会）；无精确 pin 的需求按名字。
    目录不存在时先建（冷启动首跑 <cache_root>/wheels/<plat> 必然缺失——
    pip 对缺失 --find-links 仅告警，此处裸 listdir 会 FileNotFoundError 绕过补齐）。
    只过滤顶层需求；传递依赖恒在公共索引，不受影响。"""
    os.makedirs(wheels_dir, exist_ok=True)
    vers: dict[str, set[str]] = {}
    for fn in os.listdir(wheels_dir):
        if fn.endswith(".whl"):
            name = _wheel_name(fn)
            parts = fn.split("-")
            if len(parts) >= 2:
                vers.setdefault(name, set()).add(parts[1])
    out = []
    for d in dep_list:
        name = _dep_name(d)
        ver = _dep_version(d)
        if name in vers and (not ver or _ver_hit(ver, vers[name])):
            continue
        out.append(d)
    return out


def _linux_pip_tags(spec: AppSpec, arch: str) -> list[str]:
    """Linux 交叉安装 pip 标志（★M3 阶段 2★ D-12 v5 拍板主路线 = PyPI 交叉下载）。

    平台标签按 arch：x86_64 → manylinux2014_x86_64（glibc 2.17 地板，PBS 工具链
    兼容域）；aarch64 → manylinux2014_aarch64（同 2.17 地板）；armv7l →
    manylinux_2_31/2_17_armv7l（板子 glibc 2.31 对齐，D-12 v5 主路线；PyPI 官方
    armv7l 轮已核实：pydantic-core 2.1.2 起全量覆盖）。
    """
    short = (spec.linux.python_version or "3.12.14").rsplit(".", 1)[0]  # 3.12.14 → 3.12
    tags = ["--only-binary=:all:", "--python-version", short,
            "--implementation", "cp", "--abi", "cp" + short.replace(".", "")]
    plat = {"x86_64": ["manylinux2014_x86_64", "manylinux_2_17_x86_64",
                       "linux_x86_64"],
            "aarch64": ["manylinux2014_aarch64", "manylinux_2_17_aarch64",
                        "linux_aarch64"],
            "armv7l": ["manylinux_2_31_armv7l", "manylinux_2_17_armv7l",
                       "manylinux2014_armv7l", "linux_armv7l"]}.get(arch)
    if plat is None:
        raise BuildError(f"linux 架构 {arch!r} 不支持（可选 x86_64 / aarch64 / armv7l）")
    for p in plat:
        tags += ["--platform", p]
    return tags


def _install_site_packages(stage: str, deps: tuple[str, ...],
                           wheels_dir: str, *,
                           allow_download: bool = False,
                           pip_tags: list[str] | None = None,
                           index_url: str = "",
                           extra_index_url: str = "") -> str:
    """pip --target 装入 site-packages；--no-compile（site-packages 恒只带 .py——
    目录树可写，首启 import 自动建 __pycache__ 缓存，后续命中，★v0.7 默认行为★）。

    wheels_dir 两态（★v1.2★ wheel 缓存托管；调用点缺省填托管缓存，恒非 None）：
    - 显式 --wheels-dir（allow_download=False）：纯离线供应商目录，不完整即失败；
    - 托管缓存（allow_download=True）：离线优先命中，未命中 `pip download` 在线补齐后重装
      （applocal 等非 PyPI 私有件需先入缓存，download 前按缓存剔除顶层需求）。

    pip_tags（★v1.3★ 交叉安装）：目标平台 ≠ 打包机时必须显式给目标标签
    （android：--only-binary=:all: --platform android_24_<abi> --abi cp312 …），
    install/download 全程携带；index_url / extra_index_url 透传 AppSpec
    [platforms.<平台>] 的 wheel 源配置——缺省空串 = 不干预，尊重本机 pip 配置
    （镜像等；显式 pin 主站会绕开镜像，网络抖动时 pip 会静默降级到老版本组合）。
    """
    sp_dir = os.path.join(stage, "site-packages")
    os.makedirs(sp_dir, exist_ok=True)
    if deps:
        # B.v：certifi 装入是硬约束（出网信任链）——无论用户是否声明，packager 恒装入
        dep_list = list(deps) + ([] if any(d.lower().startswith("certifi") for d in deps)
                                 else ["certifi"])
        base = [sys.executable, "-m", "pip", "install", "--no-compile",
                "--disable-pip-version-check", "--no-cache-dir",
                "--target", sp_dir] + (pip_tags or [])
        env = dict(os.environ, SOURCE_DATE_EPOCH="1577836800")  # B.u 固化

        def _run(cmd: list, what: str) -> None:
            r = subprocess.run(cmd, capture_output=True, text=True, env=env)
            if r.returncode != 0:
                raise BuildError(f"{what} 失败:\n{r.stdout[-2000:]}\n{r.stderr[-2000:]}")

        offline = base + ["--no-index", "--find-links", wheels_dir] + dep_list
        r = subprocess.run(offline, capture_output=True, text=True, env=env)
        if r.returncode != 0:
            if not allow_download:
                raise BuildError(f"pip install 失败:\n{r.stdout[-2000:]}\n{r.stderr[-2000:]}")
            missing = _uncached_deps(dep_list, wheels_dir)
            if missing:
                dl = [sys.executable, "-m", "pip", "download",
                      "--disable-pip-version-check", "-d", wheels_dir]
                if index_url:
                    dl += ["--index-url", index_url]
                if extra_index_url:
                    dl += ["--extra-index-url", extra_index_url]
                dl += (pip_tags or []) + missing
                _run(dl, f"pip download（wheel 缓存补齐 {wheels_dir}）")
                _run(offline, "pip install（wheel 缓存补齐后）")
            else:
                raise BuildError(
                    "pip install 失败（缓存已含全部顶层需求，无法在线补齐）。"
                    "常见成因：① 缓存缺传递依赖 wheel；② 缓存内有损坏 wheel"
                    "（文件名在缓存中但解析失败）——删除该 wheel 后重跑触发补齐；"
                    "③ 缓存内同名包无满足需求的版本（全局缓存他项目所留：范围/无 pin"
                    " 需求按名字判定）——删除该包全部同名 wheel 或改精确 pin（==x.y.z）"
                    "后重跑触发补齐"
                    f":\n{r.stdout[-2000:]}\n{r.stderr[-2000:]}")
        # 可复现性：direct_url.json 含本地 wheel 绝对路径 → 必删（INSTALLER 内容恒定可留）
        for du in glob.glob(os.path.join(sp_dir, "*.dist-info", "direct_url.json")):
            os.remove(du)
    return sp_dir


def _android_pip_tags(spec: AppSpec) -> list[str]:
    """Android 交叉安装 pip 标志（打包机 ≠ 目标平台，pip 必须显式给目标标签集）。

    平台标签 android_24_<abi> 为 flet 索引约定（pypi.flet.dev wheel 文件名
    cp312-cp312-android_24_*；py-android 运行时同出自 flet python-build，自洽）。
    """
    ver = spec.android.python_version or "3.12.14"
    short = ver.rsplit(".", 1)[0]                     # 3.12.14 → 3.12
    tags = ["--only-binary=:all:", "--python-version", short,
            "--implementation", "cp", "--abi", "cp" + short.replace(".", "")]
    for abi in spec.android.abis:
        # ABI 名（NDK 约定，连字符 arm64-v8a）→ wheel 平台标签（下划线 arm64_v8a）
        tags += ["--platform", "android_24_" + abi.replace("-", "_")]
    return tags


def _detect_applocal(sp_dir: str) -> str:
    """manifest.applocal_version = 实际装入的 applocal dist 版本（缺失 → 构建失败）。"""
    for dist in importlib.metadata.distributions(path=[sp_dir]):
        if dist.metadata["Name"] == "applocal":
            return dist.version
    raise BuildError("site-packages 未装入 applocal（协议 A 契约层为必装件）")
